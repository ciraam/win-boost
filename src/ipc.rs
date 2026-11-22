//! Protocole IPC sécurisé par Named Pipe Windows (`\\.\pipe\WinBoost`).
//!
//! Sécurité :
//! - ACL Windows stricte appliquée via SDDL (`ConvertStringSecurityDescriptorToSecurityDescriptorW`)
//!   autorisant uniquement `SYSTEM`, `Administrators` et le propriétaire de la session (`OW`).
//! - Drapeau `PIPE_REJECT_REMOTE_CLIENTS` empêchant toute connexion réseau SMB.
//! - Taille maximale de trame JSON plafonnée (256 Ko) pour éviter toute saturation mémoire.
//! - Validation stricte côté service de chaque `IpcRequest` (whitelist, services critiques, schéma).

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Component, Path, Prefix};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::cleaner::{self, CleanCategoryId, CleanCategoryState, CleanExecutionReport};
use crate::engine::BoostEngine;
use crate::models::{
    AppConfig, BoostSessionStats, GameEntry, LogEntry, LogLevel, PingResult, ProcessAction,
    ProcessRule, ProfileId, RunningProcessInfo, SystemCapabilities, SystemMetrics,
};
use crate::monitoring::SystemMonitor;
use crate::recovery::{is_valid_service_name, RecoveryState};
use crate::whitelist::{immutable_protection_reason, is_critical_service, normalize_exe_name};
use crate::win32_ops::{self, to_wide_null, WinServiceState};

/// Nom officiel du Named Pipe local WinBoost.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\WinBoost";

/// SDDL strict : accès complet uniquement pour SYSTEM (SY), Administrateurs (BA) et le propriétaire (OW).
/// Tout autre utilisateur local ou réseau est explicitement bloqué.
pub const PIPE_STRICT_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";

const MAX_IPC_REQUEST_BYTES: usize = 64 * 1024;
const MAX_IPC_RESPONSE_BYTES: usize = 1024 * 1024;
const SDDL_REVISION_1: u32 = 1;

/// Requête typée envoyée par `winboost-ui.exe` vers `winboost-svc.exe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    GetState { include_processes: bool },
    ToggleBoost,
    SetProfile { profile: ProfileId },
    SetAutoBoost { enabled: bool },
    QuickCleanRam,
    AddGame {
        name: String,
        exe_name: String,
        profile: ProfileId,
    },
    RemoveGame { exe_name: String },
    ToggleGameAuto { exe_name: String, enabled: bool },
    CycleGameProfile { exe_name: String },
    ToggleGameAvoidCore0 { exe_name: String },
    AddWatchedFolder { folder: String },
    RemoveWatchedFolder { folder: String },
    CycleProcessRuleAction { exe_name: String },
    AddProcessRule { exe_name: String, action: ProcessAction },
    ToggleServicePause { service_name: String, enabled: bool },
    AddUserWhitelist { exe_name: String },
    RemoveUserWhitelist { exe_name: String },
    ScanClean,
    ToggleCleanCategory { id: CleanCategoryId },
    RunClean { categories: Vec<CleanCategoryId> },
    RunPing { label: String, host: String },
    SaveManualSnapshot,
    RestoreInitialState,
    ExecutePendingCrashRecovery,
    UpdateSettings {
        launch_with_windows: bool,
        start_minimized_to_tray: bool,
        minimize_to_tray_on_close: bool,
        toast_notifications: bool,
        auto_crash_recovery: bool,
        standby_threshold_mb: u64,
    },
    ClearLogs,
    ShutdownService,
}

/// Instantané complet renvoyé à l'interface native Win32/Direct2D.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiStateSnapshot {
    pub stats: BoostSessionStats,
    pub capabilities: SystemCapabilities,
    pub metrics: SystemMetrics,
    pub svc_ram_mb: f32,
    pub cpu_history: Vec<f32>,
    pub ram_history: Vec<f32>,
    pub gpu_history: Vec<f32>,
    pub config: AppConfig,
    pub logs: Vec<LogEntry>,
    pub running_processes: Vec<RunningProcessInfo>,
    pub service_states: HashMap<String, WinServiceState>,
    pub pending_crash_summary: Option<String>,
    pub recovery_path: String,
    pub recovery_file_summary: Option<String>,
    pub clean_categories: Vec<CleanCategoryState>,
    pub clean_scanning: bool,
    pub clean_running: bool,
    pub last_clean_report: Option<CleanExecutionReport>,
    pub total_clean_freed_bytes: u64,
    pub ping_results: Vec<PingResult>,
    pub ping_running: bool,
    pub last_banner: Option<(String, bool)>,
}

/// Réponse typée renvoyée par `winboost-svc.exe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong { svc_ram_mb: f32, is_admin: bool },
    State { snapshot: Box<UiStateSnapshot> },
    Ok { message: String },
    Error { message: String },
}

/// État partagé hébergé exclusivement dans le daemon/service `winboost-svc.exe`.
pub struct ServiceBackend {
    pub engine: BoostEngine,
    pub monitor: SystemMonitor,
    pub clean_categories: Vec<CleanCategoryState>,
    pub clean_scanning: bool,
    pub clean_running: bool,
    pub last_clean_report: Option<CleanExecutionReport>,
    pub total_clean_freed_bytes: u64,
    pub ping_results: Vec<PingResult>,
    pub ping_running: bool,
    pub last_ui_heartbeat: Option<Instant>,
    pub last_banner: Option<(String, bool)>,
    pub shutdown_requested: bool,
}

impl ServiceBackend {
    pub fn new(config: AppConfig, recovery_path: std::path::PathBuf) -> Self {
        let mut monitor = SystemMonitor::new();
        monitor.paused = true; // En pause tant qu'aucun client UI n'est connecté !
        let mut engine = BoostEngine::new(config, recovery_path);
        engine.capabilities.gpu_name = monitor.gpu_name.clone();

        Self {
            engine,
            monitor,
            clean_categories: cleaner::default_clean_categories(),
            clean_scanning: false,
            clean_running: false,
            last_clean_report: None,
            total_clean_freed_bytes: 0,
            ping_results: Vec::new(),
            ping_running: false,
            last_ui_heartbeat: None,
            last_banner: None,
            shutdown_requested: false,
        }
    }

    /// Indique si un client UI est actif (requête reçue dans les 5 dernières secondes).
    pub fn has_active_ui_client(&self) -> bool {
        self.last_ui_heartbeat
            .map(|t| t.elapsed() < Duration::from_secs(5))
            .unwrap_or(false)
    }

    /// Échantillonne le monitoring UNIQUEMENT lorsqu'un client UI est connecté.
    pub fn tick_monitoring_if_ui_connected(&mut self) {
        if self.has_active_ui_client() {
            self.monitor.paused = false;
            self.monitor.sample();
        } else if !self.monitor.paused {
            self.monitor.paused = true;
            win32_ops::trim_self_working_set();
        }
    }

    pub fn build_snapshot(&mut self, include_processes: bool) -> UiStateSnapshot {
        self.last_ui_heartbeat = Some(Instant::now());
        if self.monitor.paused || self.monitor.cpu_history.len() < 2 {
            self.monitor.paused = false;
            self.monitor.sample();
        }
        if include_processes {
            self.engine.refresh_processes_and_services();
        }

        let recovery_file_summary = RecoveryState::load_from_path(&self.engine.recovery_path)
            .ok()
            .flatten()
            .map(|r| r.summary_line());

        UiStateSnapshot {
            stats: self.engine.stats.clone(),
            capabilities: self.engine.capabilities.clone(),
            metrics: self.monitor.current.clone(),
            svc_ram_mb: crate::monitoring::read_self_ram_mb(),
            cpu_history: self.monitor.cpu_history.iter().copied().collect(),
            ram_history: self.monitor.ram_history.iter().copied().collect(),
            gpu_history: self.monitor.gpu_history.iter().copied().collect(),
            config: self.engine.config.clone(),
            logs: self.engine.logs.clone(),
            running_processes: if include_processes {
                self.engine.running_processes.clone()
            } else {
                Vec::new()
            },
            service_states: self.engine.service_states.clone(),
            pending_crash_summary: self
                .engine
                .pending_crash_recovery
                .as_ref()
                .map(|r| r.summary_line()),
            recovery_path: self.engine.recovery_path.display().to_string(),
            recovery_file_summary,
            clean_categories: self.clean_categories.clone(),
            clean_scanning: self.clean_scanning,
            clean_running: self.clean_running,
            last_clean_report: self.last_clean_report.clone(),
            total_clean_freed_bytes: self.total_clean_freed_bytes,
            ping_results: self.ping_results.clone(),
            ping_running: self.ping_running,
            last_banner: self.last_banner.take(),
        }
    }
}

/// Traite une requête IPC avec validation stricte côté service.
pub fn handle_ipc_request(backend: &Arc<Mutex<ServiceBackend>>, req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Ping => {
            let b = backend.lock().unwrap();
            IpcResponse::Pong {
                svc_ram_mb: crate::monitoring::read_self_ram_mb(),
                is_admin: b.engine.capabilities.is_admin,
            }
        }
        IpcRequest::GetState { include_processes } => {
            let mut b = backend.lock().unwrap();
            let snap = b.build_snapshot(include_processes);
            IpcResponse::State {
                snapshot: Box::new(snap),
            }
        }
        IpcRequest::ToggleBoost => {
            let mut b = backend.lock().unwrap();
            if b.engine.stats.active {
                b.engine.deactivate_boost();
                IpcResponse::Ok {
                    message: "Boost désactivé — État initial restauré.".to_string(),
                }
            } else {
                b.engine.activate_manual_boost();
                IpcResponse::Ok {
                    message: "Boost activé avec snapshot NTFS atomique.".to_string(),
                }
            }
        }
        IpcRequest::SetProfile { profile } => {
            let mut b = backend.lock().unwrap();
            let name = profile.display_name();
            b.engine.set_global_profile(profile);
            IpcResponse::Ok {
                message: format!("Profil actif : {}", name),
            }
        }
        IpcRequest::SetAutoBoost { enabled } => {
            let mut b = backend.lock().unwrap();
            b.engine.config.auto_boost_enabled = enabled;
            let _ = b.engine.config.save();
            IpcResponse::Ok {
                message: if enabled {
                    "Auto-Boost activé (surveillance 2.5s).".to_string()
                } else {
                    "Auto-Boost désactivé (mode manuel).".to_string()
                },
            }
        }
        IpcRequest::QuickCleanRam => {
            let mut b = backend.lock().unwrap();
            let freed = b.engine.quick_clean_ram();
            IpcResponse::Ok {
                message: format!("Nettoyage RAM terminé : {:.1} Mo libérés.", freed),
            }
        }
        IpcRequest::AddGame {
            name,
            exe_name,
            profile,
        } => {
            let exe = normalize_exe_name(&exe_name);
            if exe.is_empty() || !exe.ends_with(".exe") || exe.len() > 128 {
                return IpcResponse::Error {
                    message: "Nom d'exécutable invalide (.exe requis).".to_string(),
                };
            }
            if immutable_protection_reason(&exe).is_some() {
                return IpcResponse::Error {
                    message: format!("{} est un processus protégé système/Anti-Cheat.", exe),
                };
            }
            let clean_name = if name.trim().is_empty() {
                exe.trim_end_matches(".exe").to_string()
            } else {
                name.trim().chars().take(64).collect()
            };
            let mut b = backend.lock().unwrap();
            if b.engine.config.games.iter().any(|g| g.exe_name == exe) {
                return IpcResponse::Error {
                    message: "Cet exécutable existe déjà dans la bibliothèque.".to_string(),
                };
            }
            b.engine.config.games.insert(
                0,
                GameEntry {
                    name: clean_name.clone(),
                    exe_name: exe.clone(),
                    full_path: None,
                    assigned_profile: profile,
                    override_avoid_core_0: None,
                    override_priority: None,
                    override_network_qos: None,
                    auto_boost_enabled: true,
                    is_custom: true,
                },
            );
            let _ = b.engine.config.save();
            b.engine.log(
                LogLevel::Success,
                "Jeux",
                format!("Jeu ajouté : {} ({})", clean_name, exe),
            );
            IpcResponse::Ok {
                message: format!("Jeu {} ajouté.", clean_name),
            }
        }
        IpcRequest::RemoveGame { exe_name } => {
            let norm = normalize_exe_name(&exe_name);
            let mut b = backend.lock().unwrap();
            let before = b.engine.config.games.len();
            b.engine
                .config
                .games
                .retain(|g| !(g.is_custom && g.exe_name == norm));
            if b.engine.config.games.len() != before {
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: format!("Jeu {} retiré.", norm),
            }
        }
        IpcRequest::ToggleGameAuto { exe_name, enabled } => {
            let norm = normalize_exe_name(&exe_name);
            let mut b = backend.lock().unwrap();
            if let Some(g) = b.engine.config.games.iter_mut().find(|g| g.exe_name == norm) {
                g.auto_boost_enabled = enabled;
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: "Configuration jeu mise à jour.".to_string(),
            }
        }
        IpcRequest::CycleGameProfile { exe_name } => {
            let norm = normalize_exe_name(&exe_name);
            let mut b = backend.lock().unwrap();
            if let Some(g) = b.engine.config.games.iter_mut().find(|g| g.exe_name == norm) {
                g.assigned_profile = match g.assigned_profile {
                    ProfileId::Balanced => ProfileId::Competitive,
                    ProfileId::Competitive => ProfileId::SilentLaptop,
                    _ => ProfileId::Balanced,
                };
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: "Profil du jeu modifié.".to_string(),
            }
        }
        IpcRequest::ToggleGameAvoidCore0 { exe_name } => {
            let norm = normalize_exe_name(&exe_name);
            let mut b = backend.lock().unwrap();
            if let Some(g) = b.engine.config.games.iter_mut().find(|g| g.exe_name == norm) {
                let cur = g.override_avoid_core_0.unwrap_or(false);
                g.override_avoid_core_0 = Some(!cur);
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: "Option Core 0 mise à jour.".to_string(),
            }
        }
        IpcRequest::AddWatchedFolder { folder } => {
            let validated = match validate_watched_folder(&folder) {
                Ok(p) => p,
                Err(msg) => return IpcResponse::Error { message: msg },
            };
            let mut b = backend.lock().unwrap();
            if !b.engine.config.watched_game_folders.contains(&validated) {
                b.engine.config.watched_game_folders.push(validated.clone());
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: format!("Dossier surveillé ajouté : {}", validated),
            }
        }
        IpcRequest::RemoveWatchedFolder { folder } => {
            let mut b = backend.lock().unwrap();
            b.engine.config.watched_game_folders.retain(|f| f != &folder);
            let _ = b.engine.config.save();
            IpcResponse::Ok {
                message: "Dossier retiré.".to_string(),
            }
        }
        IpcRequest::CycleProcessRuleAction { exe_name } => {
            let norm = normalize_exe_name(&exe_name);
            if immutable_protection_reason(&norm).is_some() {
                return IpcResponse::Error {
                    message: format!("{} est protégé par la Whitelist inviolable.", norm),
                };
            }
            let mut b = backend.lock().unwrap();
            if let Some(r) = b
                .engine
                .config
                .process_rules
                .iter_mut()
                .find(|r| r.exe_name == norm)
            {
                r.action = match r.action {
                    ProcessAction::Ignore => ProcessAction::Suspend,
                    ProcessAction::Suspend => ProcessAction::CloseGracefully,
                    ProcessAction::CloseGracefully => ProcessAction::Ignore,
                };
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: "Règle processus mise à jour.".to_string(),
            }
        }
        IpcRequest::AddProcessRule { exe_name, action } => {
            let norm = normalize_exe_name(&exe_name);
            if norm.is_empty() || !norm.ends_with(".exe") || norm.len() > 128 {
                return IpcResponse::Error {
                    message: "Exécutable invalide (.exe requis).".to_string(),
                };
            }
            if immutable_protection_reason(&norm).is_some() {
                return IpcResponse::Error {
                    message: format!(
                        "Refusé : {} est protégé par la Whitelist inviolable (OS / Anti-Cheat).",
                        norm
                    ),
                };
            }
            let mut b = backend.lock().unwrap();
            if !b
                .engine
                .config
                .process_rules
                .iter()
                .any(|r| r.exe_name == norm)
            {
                b.engine.config.process_rules.insert(
                    0,
                    ProcessRule {
                        exe_name: norm.clone(),
                        category: "Personnalisé".to_string(),
                        action,
                        is_browser_or_launcher: false,
                        is_comm_app: false,
                    },
                );
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: format!("Règle ajoutée pour {}.", norm),
            }
        }
        IpcRequest::ToggleServicePause {
            service_name,
            enabled,
        } => {
            if !is_valid_service_name(&service_name) || is_critical_service(&service_name) {
                return IpcResponse::Error {
                    message: format!(
                        "Service {} critique ou invalide : modification refusée.",
                        service_name
                    ),
                };
            }
            let mut b = backend.lock().unwrap();
            if let Some(svc) = b
                .engine
                .config
                .service_rules
                .iter_mut()
                .find(|s| s.service_name.eq_ignore_ascii_case(&service_name))
            {
                svc.enabled_for_pause = enabled;
                let svc_name = svc.service_name.clone();
                let _ = b.engine.config.save();
                IpcResponse::Ok {
                    message: format!("Service {} mis à jour.", svc_name),
                }
            } else {
                IpcResponse::Error {
                    message: "Service hors liste autorisée.".to_string(),
                }
            }
        }
        IpcRequest::AddUserWhitelist { exe_name } => {
            let norm = normalize_exe_name(&exe_name);
            if norm.is_empty() || norm.len() > 128 {
                return IpcResponse::Error {
                    message: "Nom de processus invalide.".to_string(),
                };
            }
            let mut b = backend.lock().unwrap();
            if !b.engine.config.user_whitelist.contains(&norm) {
                b.engine.config.user_whitelist.push(norm.clone());
                let _ = b.engine.config.save();
            }
            IpcResponse::Ok {
                message: format!("{} ajouté à la liste blanche.", norm),
            }
        }
        IpcRequest::RemoveUserWhitelist { exe_name } => {
            let norm = normalize_exe_name(&exe_name);
            let mut b = backend.lock().unwrap();
            b.engine.config.user_whitelist.retain(|w| w != &norm);
            let _ = b.engine.config.save();
            IpcResponse::Ok {
                message: format!("{} retiré de la liste blanche.", norm),
            }
        }
        IpcRequest::ToggleCleanCategory { id } => {
            let mut b = backend.lock().unwrap();
            if let Some(cat) = b.clean_categories.iter_mut().find(|c| c.id == id) {
                cat.selected = !cat.selected;
            }
            IpcResponse::Ok {
                message: "Catégorie mise à jour.".to_string(),
            }
        }
        IpcRequest::ScanClean => {
            {
                let mut b = backend.lock().unwrap();
                if b.clean_scanning || b.clean_running {
                    return IpcResponse::Ok {
                        message: "Analyse déjà en cours...".to_string(),
                    };
                }
                b.clean_scanning = true;
            }
            let bg = Arc::clone(backend);
            std::thread::spawn(move || {
                let scans = cleaner::scan_all_categories();
                let mut b = bg.lock().unwrap();
                b.clean_scanning = false;
                let mut total = 0u64;
                for s in scans {
                    if let Some(cat) = b.clean_categories.iter_mut().find(|c| c.id == s.id) {
                        cat.scanned = true;
                        cat.file_count = s.file_count;
                        cat.bytes_recoverable = s.bytes_recoverable;
                        total += s.bytes_recoverable;
                    }
                }
                let msg = format!(
                    "Analyse PC terminée : {} récupérables.",
                    cleaner::format_bytes(total)
                );
                b.engine.log(LogLevel::Info, "Nettoyage PC", &msg);
                b.last_banner = Some((msg, false));
            });
            IpcResponse::Ok {
                message: "Analyse du PC lancée...".to_string(),
            }
        }
        IpcRequest::RunClean { categories } => {
            if categories.is_empty() {
                return IpcResponse::Error {
                    message: "Aucune catégorie sélectionnée.".to_string(),
                };
            }
            {
                let mut b = backend.lock().unwrap();
                if b.clean_scanning || b.clean_running {
                    return IpcResponse::Error {
                        message: "Une opération de nettoyage est déjà en cours.".to_string(),
                    };
                }
                b.clean_running = true;
            }
            let bg = Arc::clone(backend);
            std::thread::spawn(move || {
                let report = cleaner::execute_clean(&categories);
                let rescans = cleaner::scan_all_categories();
                let mut b = bg.lock().unwrap();
                b.clean_running = false;
                b.total_clean_freed_bytes += report.bytes_freed;
                let msg = format!(
                    "Nettoyage terminé : {} libérés ({} supprimés, {} verrouillés ignorés).",
                    cleaner::format_bytes(report.bytes_freed),
                    report.files_deleted,
                    report.files_skipped_locked
                );
                b.engine.log(LogLevel::Success, "Nettoyage PC", &msg);
                for d in &report.details {
                    b.engine.log(LogLevel::Info, "Nettoyage PC", d);
                }
                for s in rescans {
                    if let Some(cat) = b.clean_categories.iter_mut().find(|c| c.id == s.id) {
                        cat.scanned = true;
                        cat.file_count = s.file_count;
                        cat.bytes_recoverable = s.bytes_recoverable;
                    }
                }
                b.last_clean_report = Some(report);
                b.last_banner = Some((msg, false));
            });
            IpcResponse::Ok {
                message: "Nettoyage PC lancé en arrière-plan...".to_string(),
            }
        }
        IpcRequest::RunPing { label, host } => {
            let trimmed_host = host.trim().to_string();
            if trimmed_host.is_empty()
                || trimmed_host.len() > 128
                || !trimmed_host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b':' | b'-'))
            {
                return IpcResponse::Error {
                    message: "Hôte ou adresse IP invalide.".to_string(),
                };
            }
            {
                let mut b = backend.lock().unwrap();
                if b.ping_running {
                    return IpcResponse::Ok {
                        message: "Test ping déjà en cours...".to_string(),
                    };
                }
                b.ping_running = true;
                b.engine.config.ping_custom_host = trimmed_host.clone();
            }
            let bg = Arc::clone(backend);
            std::thread::spawn(move || {
                let res = win32_ops::run_icmp_ping(&label, &trimmed_host, 4);
                let mut b = bg.lock().unwrap();
                b.ping_running = false;
                if res.error.is_none() {
                    b.monitor.record_ping_ms(res.avg_ms);
                }
                b.ping_results.insert(0, res);
                if b.ping_results.len() > 10 {
                    b.ping_results.truncate(10);
                }
            });
            IpcResponse::Ok {
                message: format!("Test ping vers {} lancé...", host),
            }
        }
        IpcRequest::SaveManualSnapshot => {
            let mut b = backend.lock().unwrap();
            match b.engine.save_manual_snapshot() {
                Ok(_) => IpcResponse::Ok {
                    message: "Snapshot atomique sauvegardé dans recovery_state.json.".to_string(),
                },
                Err(e) => IpcResponse::Error { message: e },
            }
        }
        IpcRequest::RestoreInitialState => {
            let mut b = backend.lock().unwrap();
            b.engine.deactivate_boost();
            IpcResponse::Ok {
                message: "Restauration complète exécutée.".to_string(),
            }
        }
        IpcRequest::ExecutePendingCrashRecovery => {
            let mut b = backend.lock().unwrap();
            b.engine.execute_pending_crash_recovery();
            IpcResponse::Ok {
                message: "Crash-Recovery exécuté avec succès.".to_string(),
            }
        }
        IpcRequest::UpdateSettings {
            launch_with_windows,
            start_minimized_to_tray,
            minimize_to_tray_on_close,
            toast_notifications,
            auto_crash_recovery,
            standby_threshold_mb,
        } => {
            let mut b = backend.lock().unwrap();
            if b.engine.config.launch_with_windows != launch_with_windows
                || (launch_with_windows
                    && b.engine.config.start_minimized_to_tray != start_minimized_to_tray)
            {
                if let Err(e) =
                    win32_ops::set_launch_with_windows(launch_with_windows, start_minimized_to_tray)
                {
                    return IpcResponse::Error { message: e };
                }
            }
            b.engine.config.launch_with_windows = launch_with_windows;
            b.engine.config.start_minimized_to_tray = start_minimized_to_tray;
            b.engine.config.minimize_to_tray_on_close = minimize_to_tray_on_close;
            b.engine.config.toast_notifications_enabled = toast_notifications;
            b.engine.config.auto_crash_recovery = auto_crash_recovery;
            b.engine.config.standby_purge_threshold_mb = standby_threshold_mb.clamp(512, 8192);
            let _ = b.engine.config.save();
            IpcResponse::Ok {
                message: "Paramètres enregistrés.".to_string(),
            }
        }
        IpcRequest::ClearLogs => {
            backend.lock().unwrap().engine.logs.clear();
            IpcResponse::Ok {
                message: "Journal effacé.".to_string(),
            }
        }
        IpcRequest::ShutdownService => {
            let mut b = backend.lock().unwrap();
            if b.engine.stats.active {
                b.engine.deactivate_boost();
            }
            b.shutdown_requested = true;
            IpcResponse::Ok {
                message: "Arrêt propre du service WinBoost...".to_string(),
            }
        }
    }
}

/// Construit un descripteur de sécurité Win32 strict à partir de `PIPE_STRICT_SDDL`.
struct OwnedSecurityDescriptor(*mut c_void);

impl OwnedSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, String> {
        let w = to_wide_null(sddl);
        let mut sd: *mut c_void = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            Err(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW échec (code {})",
                unsafe { GetLastError() }
            ))
        } else {
            Ok(Self(sd))
        }
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Valide strictement un dossier de jeux surveillé :
/// - Refuse les chemins vides ou trop longs (> 260 caractères)
/// - Refuse les chemins réseau UNC (`\\...`, `//...`) et préfixes NT (`\??\`)
/// - Refuse toute traversée de répertoire (`..`)
/// - Exige un lecteur local existant (`C:\...`) qui pointe vers un dossier réel (`is_dir()`).
pub fn validate_watched_folder(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 260 {
        return Err("Chemin de dossier invalide (vide ou trop long).".to_string());
    }
    if trimmed.starts_with(r"\\") || trimmed.starts_with("//") || trimmed.starts_with(r"\??\") {
        return Err("Chemins réseau UNC ou NT interdits pour les dossiers surveillés.".to_string());
    }
    if trimmed.contains("..") {
        return Err("Séquence '..' interdite dans le chemin du dossier.".to_string());
    }

    let path = Path::new(trimmed);
    let mut has_local_disk_prefix = false;
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err("Traversée de répertoire '..' interdite.".to_string());
            }
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(_) => has_local_disk_prefix = true,
                _ => {
                    return Err("Seuls les dossiers sur disque local sont autorisés.".to_string());
                }
            },
            _ => {}
        }
    }

    if !has_local_disk_prefix {
        return Err("Un chemin absolu local (ex. C:\\Jeux) est requis.".to_string());
    }
    if !path.is_dir() {
        return Err(format!("Le dossier local n'existe pas : {}", trimmed));
    }

    Ok(trimmed.to_string())
}

/// Crée une instance sécurisée de Named Pipe Windows avec :
/// - ACL SDDL stricte (`SYSTEM`, `Administrators`, `OWNER`)
/// - `PIPE_REJECT_REMOTE_CLIENTS` (rejet SMB distant)
/// - `FILE_FLAG_FIRST_PIPE_INSTANCE` sur la première instance (protection anti-pipe squatting).
fn create_secured_pipe(pipe_name: &str, is_first_instance: bool) -> Result<HANDLE, String> {
    let sd = OwnedSecurityDescriptor::from_sddl(PIPE_STRICT_SDDL)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name_w = to_wide_null(pipe_name);
    let open_mode = if is_first_instance {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        PIPE_ACCESS_DUPLEX
    };
    let handle = unsafe {
        CreateNamedPipeW(
            name_w.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            4,
            64 * 1024,
            16 * 1024,
            2000,
            &sa,
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(format!("CreateNamedPipeW échec (code {})", unsafe {
            GetLastError()
        }));
    }
    Ok(handle)
}

fn read_framed_line(handle: HANDLE, max_len: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    loop {
        let mut bytes_read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut bytes_read,
                null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE && !buf.is_empty() {
                break;
            }
            return Err(format!("ReadFile pipe code {}", err));
        }
        if bytes_read == 0 {
            break;
        }
        let slice = &chunk[..bytes_read as usize];
        if let Some(pos) = slice.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&slice[..pos]);
            break;
        }
        buf.extend_from_slice(slice);
        if buf.len() > max_len {
            return Err("Trame IPC dépassant la limite de sécurité".to_string());
        }
    }
    Ok(buf)
}

fn write_framed_line(handle: HANDLE, payload: &[u8]) -> Result<(), String> {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.extend_from_slice(payload);
    framed.push(b'\n');

    let mut written_total = 0usize;
    while written_total < framed.len() {
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                framed[written_total..].as_ptr(),
                (framed.len() - written_total) as u32,
                &mut written,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("WriteFile pipe code {}", unsafe { GetLastError() }));
        }
        written_total += written as usize;
    }
    unsafe {
        FlushFileBuffers(handle);
    }
    Ok(())
}

/// Lance la boucle serveur Named Pipe (à appeler dans un thread dédié de `winboost-svc.exe`).
///
/// La première instance est créée avec `FILE_FLAG_FIRST_PIPE_INSTANCE` (anti-pipe squatting)
/// et conservée ouverte pour réutilisation via `DisconnectNamedPipe` afin d'éliminer toute
/// fenêtre de détournement entre deux requêtes.
pub fn run_pipe_server_loop(pipe_name: String, backend: Arc<Mutex<ServiceBackend>>) {
    let pipe = match create_secured_pipe(&pipe_name, true) {
        Ok(h) => h,
        Err(e) => {
            backend.lock().unwrap().engine.log(
                LogLevel::Error,
                "Sécurité IPC",
                format!(
                    "Création exclusive du Named Pipe {} refusée (anti-squatting) : {}",
                    pipe_name, e
                ),
            );
            return;
        }
    };

    loop {
        if backend.lock().unwrap().shutdown_requested {
            break;
        }

        let connected = unsafe {
            let ok = ConnectNamedPipe(pipe, null_mut());
            ok != 0 || GetLastError() == ERROR_PIPE_CONNECTED
        };

        if connected {
            let response = match read_framed_line(pipe, MAX_IPC_REQUEST_BYTES) {
                Ok(raw) => match serde_json::from_slice::<IpcRequest>(&raw) {
                    Ok(req) => handle_ipc_request(&backend, req),
                    Err(e) => IpcResponse::Error {
                        message: format!("Requête IPC JSON invalide : {}", e),
                    },
                },
                Err(e) => IpcResponse::Error { message: e },
            };

            if let Ok(resp_bytes) = serde_json::to_vec(&response) {
                let _ = write_framed_line(pipe, &resp_bytes);
            }
        }

        unsafe {
            DisconnectNamedPipe(pipe);
        }

        if backend.lock().unwrap().shutdown_requested {
            break;
        }
    }

    unsafe {
        CloseHandle(pipe);
    }
}

/// Client Named Pipe léger utilisé par `winboost-ui.exe`.
#[derive(Clone)]
pub struct IpcClient {
    pipe_name: String,
}

impl IpcClient {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    pub fn default_pipe() -> Self {
        Self::new(DEFAULT_PIPE_NAME)
    }

    /// Envoie une requête JSON typée vers `winboost-svc.exe` et attend la réponse.
    pub fn send(&self, request: &IpcRequest) -> Result<IpcResponse, String> {
        let name_w = to_wide_null(&self.pipe_name);
        let mut attempts = 0u32;

        let handle = loop {
            let h = unsafe {
                CreateFileW(
                    name_w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0 as FILE_FLAGS_AND_ATTRIBUTES,
                    null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                break h;
            }
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY && attempts < 15 {
                attempts += 1;
                unsafe {
                    WaitNamedPipeW(name_w.as_ptr(), 200);
                }
                continue;
            }
            if err == ERROR_FILE_NOT_FOUND && attempts < 12 {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            return Err(format!("Service WinBoost non joignable (code {})", err));
        };

        let payload = serde_json::to_vec(request).map_err(|e| e.to_string())?;
        let res = (|| -> Result<IpcResponse, String> {
            write_framed_line(handle, &payload)?;
            let raw = read_framed_line(handle, MAX_IPC_RESPONSE_BYTES)?;
            serde_json::from_slice::<IpcResponse>(&raw)
                .map_err(|e| format!("Réponse IPC invalide : {}", e))
        })();

        unsafe {
            CloseHandle(handle);
        }
        res
    }

    pub fn is_service_alive(&self) -> bool {
        matches!(self.send(&IpcRequest::Ping), Ok(IpcResponse::Pong { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_sddl_security_descriptor_builds() {
        let sd = OwnedSecurityDescriptor::from_sddl(PIPE_STRICT_SDDL);
        assert!(sd.is_ok(), "SDDL strict doit compiler proprement: {:?}", sd.err());
    }

    #[test]
    fn test_server_rejects_whitelisted_and_critical_ipc_requests() {
        let tmp_rec = std::env::temp_dir().join(format!("wb_ipc_sec_{}.json", std::process::id()));
        let backend = Arc::new(Mutex::new(ServiceBackend::new(AppConfig::default(), tmp_rec)));

        // Tentative d'ajouter un Anti-Cheat aux règles processus -> rejetée
        let resp1 = handle_ipc_request(
            &backend,
            IpcRequest::AddProcessRule {
                exe_name: "vgc.exe".to_string(),
                action: ProcessAction::Suspend,
            },
        );
        assert!(matches!(resp1, IpcResponse::Error { .. }));

        // Tentative de modifier un service critique Windows -> rejetée
        let resp2 = handle_ipc_request(
            &backend,
            IpcRequest::ToggleServicePause {
                service_name: "RpcSs".to_string(),
                enabled: true,
            },
        );
        assert!(matches!(resp2, IpcResponse::Error { .. }));

        // Tentative de ping avec injection caractères spéciaux -> rejetée
        let resp3 = handle_ipc_request(
            &backend,
            IpcRequest::RunPing {
                label: "Bad".to_string(),
                host: "1.1.1.1 && calc".to_string(),
            },
        );
        assert!(matches!(resp3, IpcResponse::Error { .. }));
    }

    #[test]
    fn test_named_pipe_client_server_roundtrip() {
        let pipe_name = format!(r"\\.\pipe\WinBoost_Test_{}", std::process::id());
        let tmp_rec = std::env::temp_dir().join(format!("wb_ipc_rt_{}.json", std::process::id()));
        let backend = Arc::new(Mutex::new(ServiceBackend::new(AppConfig::default(), tmp_rec)));

        let srv_backend = Arc::clone(&backend);
        let srv_pipe = pipe_name.clone();
        let handle = std::thread::spawn(move || {
            run_pipe_server_loop(srv_pipe, srv_backend);
        });

        // Attend que le serveur crée le pipe
        std::thread::sleep(Duration::from_millis(80));

        let client = IpcClient::new(&pipe_name);
        let pong = client.send(&IpcRequest::Ping).expect("Ping IPC réussi");
        assert!(matches!(pong, IpcResponse::Pong { .. }));

        let state = client
            .send(&IpcRequest::GetState {
                include_processes: false,
            })
            .expect("GetState IPC réussi");
        assert!(matches!(state, IpcResponse::State { .. }));

        let shut = client
            .send(&IpcRequest::ShutdownService)
            .expect("ShutdownService réussi");
        assert!(matches!(shut, IpcResponse::Ok { .. }));

        let _ = handle.join();
    }

    #[test]
    fn test_anti_pipe_squatting_first_pipe_instance_blocks_second_creator() {
        let pipe_name = format!(r"\\.\pipe\WinBoost_SquatTest_{}", std::process::id());
        let first = create_secured_pipe(&pipe_name, true).expect("Première instance créée");
        // Une seconde création avec FILE_FLAG_FIRST_PIPE_INSTANCE doit être refusée par Windows
        let second = create_secured_pipe(&pipe_name, true);
        assert!(
            second.is_err(),
            "FILE_FLAG_FIRST_PIPE_INSTANCE doit bloquer tout squatter déjà présent"
        );
        unsafe {
            CloseHandle(first);
        }
    }

    #[test]
    fn test_add_watched_folder_rejects_unc_traversal_and_missing_dirs() {
        assert!(validate_watched_folder(r"\\attacker\share\games").is_err());
        assert!(validate_watched_folder("//attacker/share/games").is_err());
        assert!(validate_watched_folder(r"C:\Games\..\Windows\System32").is_err());
        assert!(validate_watched_folder(r"Z:\DossierQuiNExistePas_WinBoost_9999").is_err());
        assert!(validate_watched_folder("relative/folder").is_err());

        // Un vrai dossier local existant (%TEMP%) doit être accepté
        let temp_str = std::env::temp_dir().display().to_string();
        assert!(validate_watched_folder(&temp_str).is_ok());

        let tmp_rec = std::env::temp_dir().join(format!("wb_ipc_wf_{}.json", std::process::id()));
        let backend = Arc::new(Mutex::new(ServiceBackend::new(AppConfig::default(), tmp_rec)));
        let bad = handle_ipc_request(
            &backend,
            IpcRequest::AddWatchedFolder {
                folder: r"\\evil-smb\share".to_string(),
            },
        );
        assert!(matches!(bad, IpcResponse::Error { .. }));
    }
}
