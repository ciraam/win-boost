use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

use crate::models::AppConfig;
use crate::win32_ops::to_wide_null;

/// Enregistrement d'un processus suspendu via `NtSuspendProcess`.
/// Le champ `creation_time` (FILETIME 64-bit Win32) garantit qu'on ne reprendra
/// jamais un PID recyclé appartenant à un autre processus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspendedProcessRecord {
    pub pid: u32,
    pub exe_name: String,
    pub creation_time: u64,
}

/// Enregistrement d'une modification de priorité ou d'affinité CPU d'un processus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessPriorityRecord {
    pub pid: u32,
    pub exe_name: String,
    pub creation_time: u64,
    pub original_priority_class: u32,
    pub original_affinity_mask: Option<usize>,
}

/// Enregistrement d'un service Windows arrêté/mis en pause pendant le boost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecoveryRecord {
    pub service_name: String,
    pub was_running: bool,
    pub was_paused: bool,
}

/// Enregistrement d'un paramètre registre modifié de manière réversible (ex. Mode Jeu).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryRecoveryRecord {
    pub hive: String, // "HKCU" ou "HKLM"
    pub subkey: String,
    pub value_name: String,
    pub existed_before: bool,
    pub previous_dword: Option<u32>,
}

/// Snapshot complet sauvegardé avant/pendant une session de boost dans `recovery_state.json`.
/// Permet la restauration exacte à la fin de la session ET le Crash-Recovery au redémarrage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryState {
    pub schema_version: u32,
    pub session_id: String,
    pub created_at: DateTime<Local>,
    pub trigger_source: String,
    pub profile_name: String,
    pub restored: bool,
    pub original_power_plan_guid: Option<String>,
    pub original_power_plan_name: Option<String>,
    pub suspended_processes: Vec<SuspendedProcessRecord>,
    pub modified_priorities: Vec<ProcessPriorityRecord>,
    pub stopped_services: Vec<ServiceRecoveryRecord>,
    pub created_qos_policy_names: Vec<String>,
    pub registry_changes: Vec<RegistryRecoveryRecord>,
}

/// Validation stricte (allowlist) des clés registre pouvant être restaurées depuis `recovery_state.json`.
/// Empêche toute élévation de privilège ou altération arbitraire du registre si le JSON a été modifié.
pub fn is_allowed_recovery_registry_record(rec: &RegistryRecoveryRecord) -> bool {
    let hive_ok = rec.hive.eq_ignore_ascii_case("HKCU");
    let subkey_norm = rec.subkey.trim().replace('/', "\\");
    let subkey_ok = subkey_norm.eq_ignore_ascii_case(r"Software\Microsoft\GameBar");
    let value_ok = rec.value_name.eq_ignore_ascii_case("AutoGameModeEnabled");
    hive_ok && subkey_ok && value_ok
}

/// Validation stricte d'un nom de stratégie QoS créé par WinBoost (`WinBoost_*`).
/// Interdit tout séparateur de chemin (`\`, `/`, `..`) afin d'empêcher `RegDeleteTreeW` hors scope.
pub fn is_valid_qos_policy_name(name: &str) -> bool {
    if !name.starts_with("WinBoost_") || name.len() <= "WinBoost_".len() || name.len() > 64 {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validation stricte d'un nom de service Windows (sans espaces ni caractères de traversée).
pub fn is_valid_service_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 128
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// Validation stricte d'un GUID Windows (format 8-4-4-4-12 hexadécimal).
pub fn is_valid_power_guid(guid: &str) -> bool {
    let bytes = guid.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

impl RecoveryState {
    pub fn new(trigger_source: impl Into<String>, profile_name: impl Into<String>) -> Self {
        let now = Local::now();
        Self {
            schema_version: 1,
            session_id: format!("wb-{}", now.format("%Y%m%d-%H%M%S-%3f")),
            created_at: now,
            trigger_source: trigger_source.into(),
            profile_name: profile_name.into(),
            restored: false,
            original_power_plan_guid: None,
            original_power_plan_name: None,
            suspended_processes: Vec::new(),
            modified_priorities: Vec::new(),
            stopped_services: Vec::new(),
            created_qos_policy_names: Vec::new(),
            registry_changes: Vec::new(),
        }
    }

    pub fn default_path() -> PathBuf {
        AppConfig::data_dir().join("recovery_state.json")
    }

    /// Indique s'il reste des éléments à restaurer.
    #[allow(dead_code)]
    pub fn has_pending_changes(&self) -> bool {
        !self.restored
            && (self.original_power_plan_guid.is_some()
                || !self.suspended_processes.is_empty()
                || !self.modified_priorities.is_empty()
                || !self.stopped_services.is_empty()
                || !self.created_qos_policy_names.is_empty()
                || !self.registry_changes.is_empty())
    }

    /// Sauvegarde véritablement atomique sur NTFS via `File::sync_all()` +
    /// `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
    /// Aucune fenêtre sans fichier entre la suppression et le remplacement.
    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Création dossier impossible: {}", e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Sérialisation recovery_state.json impossible: {}", e))?;
        let tmp_path = path.with_extension("json.tmp");

        {
            let mut file = std::fs::File::create(&tmp_path)
                .map_err(|e| format!("Création fichier temporaire impossible: {}", e))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("Écriture temporaire recovery_state impossible: {}", e))?;
            file.sync_all()
                .map_err(|e| format!("Synchronisation disque recovery_state impossible: {}", e))?;
        }

        let tmp_w = to_wide_null(&tmp_path.to_string_lossy());
        let dst_w = to_wide_null(&path.to_string_lossy());
        let ok = unsafe {
            MoveFileExW(
                tmp_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!(
                "Remplacement atomique MoveFileExW échoué (code Win32 {})",
                err
            ));
        }
        Ok(())
    }

    /// Charge `recovery_state.json` s'il existe.
    pub fn load_from_path(path: &Path) -> Result<Option<Self>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Lecture recovery_state.json impossible: {}", e))?;
        let state: RecoveryState = serde_json::from_str(&content)
            .map_err(|e| format!("JSON recovery_state invalide: {}", e))?;
        Ok(Some(state))
    }

    /// Détecte si un snapshot non restauré existe (crash ou arrêt brutal lors d'une session précédente).
    pub fn detect_unrestored(path: &Path) -> Result<Option<Self>, String> {
        match Self::load_from_path(path)? {
            Some(state) if !state.restored => Ok(Some(state)),
            _ => Ok(None),
        }
    }

    /// Marque l'état comme restauré et nettoie le fichier de reprise.
    pub fn mark_restored_and_cleanup(&mut self, path: &Path) -> Result<(), String> {
        self.restored = true;
        let _ = self.save_atomic(path);
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| format!("Suppression recovery_state.json impossible: {}", e))?;
        }
        Ok(())
    }

    /// Résumé lisible du contenu du snapshot pour l'UI et les logs.
    pub fn summary_line(&self) -> String {
        format!(
            "Session {} ({}) : {} proc. suspendus, {} priorités, {} services, {} QoS, plan initial: {}",
            self.session_id,
            self.profile_name,
            self.suspended_processes.len(),
            self.modified_priorities.len(),
            self.stopped_services.len(),
            self.created_qos_policy_names.len(),
            self.original_power_plan_name
                .as_deref()
                .or(self.original_power_plan_guid.as_deref())
                .unwrap_or("Inchangé"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_recovery_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("winboost_test_{}_{}.json", name, std::process::id()));
        p
    }

    #[test]
    fn test_recovery_state_atomic_save_load_and_crash_detection() {
        let path = temp_recovery_path("atomic_crash");
        let _ = std::fs::remove_file(&path);

        let mut state = RecoveryState::new("cs2.exe", "Compétitif / Max FPS");
        assert!(state.session_id.starts_with("wb-"));
        state.original_power_plan_guid = Some("381b4222-f694-41f0-9685-ff5bb260df2e".to_string());
        state.original_power_plan_name = Some("Usage normal".to_string());
        state.suspended_processes.push(SuspendedProcessRecord {
            pid: 4242,
            exe_name: "chrome.exe".to_string(),
            creation_time: 133700000000000000,
        });
        state.stopped_services.push(ServiceRecoveryRecord {
            service_name: "WSearch".to_string(),
            was_running: true,
            was_paused: false,
        });
        state.created_qos_policy_names.push("WinBoost_Game".to_string());

        assert!(state.has_pending_changes());
        state.save_atomic(&path).expect("sauvegarde atomique réussie");
        // Seconde sauvegarde atomique en écrasement direct (MoveFileExW REPLACE_EXISTING)
        state.save_atomic(&path).expect("remplacement atomique réussi");

        let detected = RecoveryState::detect_unrestored(&path)
            .expect("lecture OK")
            .expect("état non restauré détecté");
        assert_eq!(detected.trigger_source, "cs2.exe");
        assert_eq!(detected.suspended_processes.len(), 1);
        assert_eq!(detected.suspended_processes[0].pid, 4242);
        assert_eq!(detected.suspended_processes[0].creation_time, 133700000000000000);
        assert_eq!(detected.stopped_services[0].service_name, "WSearch");
        assert_eq!(
            detected.original_power_plan_guid.as_deref(),
            Some("381b4222-f694-41f0-9685-ff5bb260df2e")
        );

        let mut to_restore = detected;
        to_restore
            .mark_restored_and_cleanup(&path)
            .expect("nettoyage OK");
        assert!(to_restore.restored);
        assert!(!to_restore.has_pending_changes());
        assert!(!path.exists());
        assert!(RecoveryState::detect_unrestored(&path).unwrap().is_none());
    }

    #[test]
    fn test_recovery_state_roundtrip_registry_and_priority() {
        let path = temp_recovery_path("roundtrip_reg");
        let _ = std::fs::remove_file(&path);

        let mut state = RecoveryState::new("Manuel", "Équilibré");
        state.modified_priorities.push(ProcessPriorityRecord {
            pid: 9001,
            exe_name: "eldenring.exe".to_string(),
            creation_time: 999888777,
            original_priority_class: 0x20,
            original_affinity_mask: Some(0xFFFF),
        });
        state.registry_changes.push(RegistryRecoveryRecord {
            hive: "HKCU".to_string(),
            subkey: r"Software\Microsoft\GameBar".to_string(),
            value_name: "AutoGameModeEnabled".to_string(),
            existed_before: true,
            previous_dword: Some(0),
        });

        state.save_atomic(&path).unwrap();
        let loaded = RecoveryState::load_from_path(&path).unwrap().unwrap();
        assert_eq!(loaded.modified_priorities, state.modified_priorities);
        assert_eq!(loaded.registry_changes, state.registry_changes);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_recovery_security_validators_block_tampering() {
        // Registre autorisé : uniquement HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled
        let valid_reg = RegistryRecoveryRecord {
            hive: "HKCU".to_string(),
            subkey: r"Software\Microsoft\GameBar".to_string(),
            value_name: "AutoGameModeEnabled".to_string(),
            existed_before: true,
            previous_dword: Some(1),
        };
        assert!(is_allowed_recovery_registry_record(&valid_reg));

        let tampered_hklm = RegistryRecoveryRecord {
            hive: "HKLM".to_string(),
            subkey: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value_name: "Evil".to_string(),
            existed_before: false,
            previous_dword: None,
        };
        assert!(!is_allowed_recovery_registry_record(&tampered_hklm));

        // QoS policy validation : préfixe WinBoost_ strict sans traversée
        assert!(is_valid_qos_policy_name("WinBoost_ActiveGame"));
        assert!(!is_valid_qos_policy_name("WinBoost_"));
        assert!(!is_valid_qos_policy_name(r"WinBoost_..\Other"));
        assert!(!is_valid_qos_policy_name("OtherPolicy"));

        // Validation GUID plan d'alimentation
        assert!(is_valid_power_guid("381b4222-f694-41f0-9685-ff5bb260df2e"));
        assert!(!is_valid_power_guid("invalid-guid"));
        assert!(!is_valid_power_guid("381b4222-f694-41f0-9685-ff5bb260df2e && calc"));

        // Validation nom de service
        assert!(is_valid_service_name("WSearch"));
        assert!(!is_valid_service_name("../evil"));
        assert!(!is_valid_service_name("svc name with spaces"));
    }
}
