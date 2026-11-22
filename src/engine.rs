//! Moteur principal d'optimisation réversible (`BoostEngine`).
//!
//! Coordonne :
//! - Le snapshot pré-boost et la persistance atomique dans `recovery_state.json`
//! - La détection automatique des jeux (Auto-Boost)
//! - L'application sûre des profils (Alimentation, CPU, RAM, Processus, Services, Réseau QoS)
//! - La restauration automatique complète et le Crash-Recovery au démarrage

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Local;

use crate::models::{
    AppConfig, BoostProfile, BoostSessionStats, GameEntry, LogEntry, LogLevel, ProcessAction,
    ProfileId, RunningProcessInfo, SystemCapabilities,
};
use crate::monitoring::SystemMonitor;
use crate::recovery::{
    ProcessPriorityRecord, RecoveryState, ServiceRecoveryRecord, SuspendedProcessRecord,
};
use crate::whitelist::{check_protection, immutable_protection_reason, normalize_exe_name};
use crate::win32_ops::{self, WinServiceState};

const MAX_LOG_ENTRIES: usize = 400;
const STANDBY_PURGE_COOLDOWN: Duration = Duration::from_secs(60);

pub struct BoostEngine {
    pub config: AppConfig,
    pub recovery_path: PathBuf,
    pub active_recovery: Option<RecoveryState>,
    pub pending_crash_recovery: Option<RecoveryState>,
    pub stats: BoostSessionStats,
    pub capabilities: SystemCapabilities,
    pub logs: Vec<LogEntry>,
    pub running_processes: Vec<RunningProcessInfo>,
    pub service_states: HashMap<String, WinServiceState>,
    pub last_standby_purge: Option<Instant>,
    pub last_toast_message: Option<String>,
    /// Vrai si le boost en cours a été déclenché automatiquement par la détection d'un jeu.
    pub triggered_by_auto_detect: bool,
    /// PID + temps de création du jeu détecté afin de détecter sa fermeture exacte.
    pub tracked_game_instance: Option<(u32, u64, String)>,
}

impl BoostEngine {
    pub fn new(config: AppConfig, recovery_path: PathBuf) -> Self {
        let mut engine = Self {
            config,
            recovery_path,
            active_recovery: None,
            pending_crash_recovery: None,
            stats: BoostSessionStats::default(),
            capabilities: SystemCapabilities::default(),
            logs: Vec::with_capacity(128),
            running_processes: Vec::new(),
            service_states: HashMap::new(),
            last_standby_purge: None,
            last_toast_message: None,
            triggered_by_auto_detect: false,
            tracked_game_instance: None,
        };

        engine.refresh_capabilities();
        engine.log(
            LogLevel::Info,
            "Système",
            format!(
                "WinBoost initialisé ({}, privilèges: {}, {} cœurs logiques).",
                engine.capabilities.os_label,
                if engine.capabilities.is_admin {
                    "Administrateur"
                } else {
                    "Standard"
                },
                engine.capabilities.logical_cpu_count
            ),
        );

        // Vérification Crash-Recovery au démarrage
        engine.check_and_handle_crash_recovery();
        engine
    }

    pub fn log(&mut self, level: LogLevel, category: impl Into<String>, message: impl Into<String>) {
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.remove(0);
        }
        self.logs.push(LogEntry {
            timestamp: Local::now(),
            level,
            category: category.into(),
            message: message.into(),
        });
    }

    pub fn refresh_capabilities(&mut self) {
        let power = win32_ops::get_active_power_plan();
        self.capabilities = SystemCapabilities {
            is_admin: win32_ops::is_elevated(),
            game_mode_enabled: win32_ops::is_windows_game_mode_enabled(),
            hags_enabled: win32_ops::is_hags_enabled(),
            active_power_plan_guid: power.as_ref().map(|(g, _)| g.clone()),
            active_power_plan_name: power
                .map(|(_, n)| n)
                .unwrap_or_else(|| "Inconnu".to_string()),
            logical_cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            gpu_name: String::new(),
            os_label: win32_ops::detect_windows_label(),
        };
    }

    /// Inspecte `recovery_state.json` au démarrage pour restaurer tout état laissé suite à un crash.
    pub fn check_and_handle_crash_recovery(&mut self) {
        match RecoveryState::detect_unrestored(&self.recovery_path) {
            Ok(Some(unrestored)) => {
                self.log(
                    LogLevel::Warning,
                    "Crash-Recovery",
                    format!(
                        "État non restauré détecté suite à un arrêt brutal : {}",
                        unrestored.summary_line()
                    ),
                );
                if self.config.auto_crash_recovery {
                    self.log(
                        LogLevel::Info,
                        "Crash-Recovery",
                        "Exécution automatique de la restauration de l'état d'origine...",
                    );
                    self.restore_state_object(unrestored);
                } else {
                    self.pending_crash_recovery = Some(unrestored);
                }
            }
            Ok(None) => {}
            Err(e) => {
                self.log(
                    LogLevel::Error,
                    "Crash-Recovery",
                    format!("Impossible de lire recovery_state.json : {}", e),
                );
            }
        }
    }

    /// Exécute manuellement le Crash-Recovery en attente (si le mode auto était désactivé).
    pub fn execute_pending_crash_recovery(&mut self) {
        if let Some(state) = self.pending_crash_recovery.take() {
            self.restore_state_object(state);
        }
    }

    /// Rafraîchit la liste des processus actifs et l'état des services configurés (uniquement quand visible).
    pub fn refresh_processes_and_services(&mut self) {
        let suspended_pids: HashSet<u32> = self
            .active_recovery
            .as_ref()
            .map(|r| r.suspended_processes.iter().map(|p| p.pid).collect())
            .unwrap_or_default();

        let raw = win32_ops::enumerate_processes(true);
        let mut list: Vec<RunningProcessInfo> = raw
            .into_iter()
            .filter(|p| p.pid > 0)
            .map(|p| {
                let norm = normalize_exe_name(&p.exe_name);
                let is_imm = immutable_protection_reason(&p.exe_name).is_some();
                let is_uwl = self
                    .config
                    .user_whitelist
                    .iter()
                    .any(|w| normalize_exe_name(w) == norm);
                RunningProcessInfo {
                    pid: p.pid,
                    name: p.exe_name,
                    full_path: p.full_path,
                    ram_mb: p.working_set_bytes as f64 / (1024.0 * 1024.0),
                    creation_time: p.creation_time,
                    is_immutable_protected: is_imm,
                    is_user_whitelisted: is_uwl,
                    is_suspended_by_us: suspended_pids.contains(&p.pid),
                }
            })
            .collect();

        list.sort_by(|a, b| {
            b.ram_mb
                .partial_cmp(&a.ram_mb)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        self.running_processes = list;

        // État des services Windows configurés
        for svc in &self.config.service_rules {
            let st = win32_ops::query_service_state(&svc.service_name);
            self.service_states.insert(svc.service_name.clone(), st);
        }
    }

    /// Cycle léger de détection automatique des jeux (appelé toutes les 2.5 s par le thread de fond).
    /// Retourne `Some(toast_msg)` si une notification doit être affichée.
    pub fn poll_auto_boost(&mut self) -> Option<String> {
        if !self.config.auto_boost_enabled {
            return None;
        }

        // Si un jeu est déjà suivi, vérifier s'il tourne toujours
        if let Some((game_pid, game_ct, ref game_name)) = self.tracked_game_instance.clone() {
            let still_alive = match win32_ops::get_process_creation_time(game_pid) {
                Some(ct) => game_ct == 0 || ct == game_ct,
                None => false,
            };

            if !still_alive {
                self.log(
                    LogLevel::Info,
                    "Auto-Boost",
                    format!(
                        "Fermeture détectée de {} (PID {}). Restauration automatique...",
                        game_name, game_pid
                    ),
                );
                self.tracked_game_instance = None;
                if self.stats.active && self.triggered_by_auto_detect {
                    self.deactivate_boost();
                    return Some(format!(
                        "Fin de session {} — État système initial restauré.",
                        game_name
                    ));
                }
            } else if self.stats.active {
                // Vérification intelligente de la Standby List pendant la partie (avec cooldown >= 60s)
                self.maybe_purge_standby_during_session();
            }
            return None;
        }

        // Si un boost manuel est déjà actif, ne pas interférer
        if self.stats.active {
            return None;
        }

        // Scan léger des processus (chemins résolus uniquement si des dossiers surveillés existent)
        let need_paths = !self.config.watched_game_folders.is_empty();
        let procs = win32_ops::enumerate_processes(need_paths);
        for p in procs {
            if let Some(game) = self
                .config
                .match_game_process(&p.exe_name, p.full_path.as_deref())
            {
                let ct = if p.creation_time != 0 {
                    p.creation_time
                } else {
                    win32_ops::get_process_creation_time(p.pid).unwrap_or(0)
                };
                let profile = game.resolve_profile(&self.config.profiles);
                self.log(
                    LogLevel::Success,
                    "Auto-Boost",
                    format!(
                        "Jeu détecté : {} ({}, PID {}) — Profil « {} »",
                        game.name,
                        p.exe_name,
                        p.pid,
                        profile.id.display_name()
                    ),
                );
                self.triggered_by_auto_detect = true;
                self.tracked_game_instance = Some((p.pid, ct, game.name.clone()));
                self.activate_boost_with_profile(Some((game.clone(), p.pid)), profile);
                return Some(format!(
                    "Boost activé pour {} (Profil {})",
                    game.name,
                    self.stats.active_profile_name
                ));
            }
        }
        None
    }

    /// Active le Boost en mode manuel avec le profil global sélectionné.
    pub fn activate_manual_boost(&mut self) {
        if self.stats.active {
            return;
        }
        let profile = self.config.active_profile();
        self.triggered_by_auto_detect = false;
        self.tracked_game_instance = None;
        self.activate_boost_with_profile(None, profile);
    }

    /// Active un profil d'optimisation complet en créant d'abord le snapshot `recovery_state.json`.
    pub fn activate_boost_with_profile(
        &mut self,
        detected_game: Option<(GameEntry, u32)>,
        profile: BoostProfile,
    ) {
        if self.stats.active {
            return;
        }

        let trigger_label = detected_game
            .as_ref()
            .map(|(g, _)| g.name.clone())
            .unwrap_or_else(|| "Boost Manuel".to_string());
        let profile_name = profile.id.display_name();

        // 1. SNAPSHOT INITIAL AVANT TOUTE MODIFICATION
        let mut recovery = RecoveryState::new(&trigger_label, &profile_name);
        if let Some((guid, name)) = win32_ops::get_active_power_plan() {
            recovery.original_power_plan_guid = Some(guid);
            recovery.original_power_plan_name = Some(name);
        }

        if let Err(e) = recovery.save_atomic(&self.recovery_path) {
            self.log(
                LogLevel::Error,
                "Snapshot",
                format!("Échec sauvegarde pré-boost : {}", e),
            );
            return;
        }
        self.log(
            LogLevel::Info,
            "Snapshot",
            format!(
                "Snapshot initial sauvegardé ({}) — Plan initial : {}",
                recovery.session_id,
                recovery
                    .original_power_plan_name
                    .as_deref()
                    .unwrap_or("Inconnu")
            ),
        );

        let mut ram_freed_bytes: u64 = 0;
        let mut closed_count = 0usize;
        let mut active_power_label = recovery
            .original_power_plan_name
            .clone()
            .unwrap_or_else(|| "Actuel".to_string());

        // 2. PLAN D'ALIMENTATION
        match win32_ops::apply_power_plan_target(profile.power_plan) {
            Ok((_, label)) => {
                active_power_label = label.clone();
                self.log(
                    LogLevel::Success,
                    "Alimentation",
                    format!("Plan d'alimentation activé : {}", label),
                );
            }
            Err(e) => {
                self.log(
                    LogLevel::Warning,
                    "Alimentation",
                    format!("Changement de plan ignoré : {}", e),
                );
            }
        }

        // 3. MODE JEU WINDOWS (réversible)
        if profile.enable_game_mode {
            match win32_ops::enable_windows_game_mode_reversible() {
                Ok(Some(rec)) => {
                    recovery.registry_changes.push(rec);
                    self.log(
                        LogLevel::Success,
                        "Windows",
                        "Mode Jeu Windows activé (sera restauré après la session).",
                    );
                }
                Ok(None) => {
                    self.log(LogLevel::Info, "Windows", "Mode Jeu Windows déjà actif.");
                }
                Err(e) => {
                    self.log(
                        LogLevel::Warning,
                        "Windows",
                        format!("Mode Jeu non modifié : {}", e),
                    );
                }
            }
        }

        // 4. PRIORITÉ & AFFINITÉ CPU DU JEU ACTIF
        let active_game_exe = detected_game.as_ref().map(|(g, _)| g.exe_name.clone());
        if let Some((ref game, game_pid)) = detected_game {
            match win32_ops::apply_game_cpu_optimization(
                game_pid,
                profile.game_cpu_priority,
                profile.avoid_core_0,
            ) {
                Ok((ct, old_prio, old_aff)) => {
                    recovery.modified_priorities.push(ProcessPriorityRecord {
                        pid: game_pid,
                        exe_name: game.exe_name.clone(),
                        creation_time: ct,
                        original_priority_class: old_prio,
                        original_affinity_mask: old_aff,
                    });
                    self.log(
                        LogLevel::Success,
                        "CPU",
                        format!(
                            "{} (PID {}) → Priorité {}{}",
                            game.exe_name,
                            game_pid,
                            profile.game_cpu_priority.label(),
                            if old_aff.is_some() {
                                " + Affinité hors Core 0"
                            } else {
                                ""
                            }
                        ),
                    );
                }
                Err(e) => {
                    self.log(LogLevel::Warning, "CPU", e);
                }
            }
        }

        // 5. SUSPENSION / FERMETURE INTELLIGENTE & NETTOYAGE WORKING SET
        let rules = self.config.process_rule_map();
        let all_procs = win32_ops::enumerate_processes(false);
        let active_game_pid = detected_game.as_ref().map(|(_, pid)| *pid);

        for proc_entry in &all_procs {
            if proc_entry.pid <= 4 || Some(proc_entry.pid) == active_game_pid {
                continue;
            }

            // GARDE-FOU INVIOLABLE : ne jamais toucher un processus protégé
            if check_protection(
                &proc_entry.exe_name,
                &self.config.user_whitelist,
                active_game_exe.as_deref(),
            )
            .is_some()
            {
                continue;
            }

            let norm = normalize_exe_name(&proc_entry.exe_name);

            // Nettoyage RAM Working Set sûr sur processus utilisateur en arrière-plan
            if profile.trim_working_sets {
                ram_freed_bytes += win32_ops::trim_process_working_set(proc_entry.pid);
            }

            // Règle spécifique de suspension / fermeture propre
            if let Some(rule) = rules.get(&norm) {
                let allowed_by_profile = if rule.is_browser_or_launcher {
                    profile.suspend_browsers_and_launchers
                } else if rule.is_comm_app {
                    profile.suspend_comm_apps
                } else {
                    true
                };

                if !allowed_by_profile {
                    continue;
                }

                match rule.action {
                    ProcessAction::Ignore => {}
                    ProcessAction::Suspend => {
                        match win32_ops::suspend_process(proc_entry.pid) {
                            Ok(ct) => {
                                recovery.suspended_processes.push(SuspendedProcessRecord {
                                    pid: proc_entry.pid,
                                    exe_name: proc_entry.exe_name.clone(),
                                    creation_time: ct,
                                });
                            }
                            Err(_) => {
                                // Silencieux si accès refusé par manque d'élévation pour un sous-processus protégé
                            }
                        }
                    }
                    ProcessAction::CloseGracefully => {
                        if win32_ops::close_process_gracefully(proc_entry.pid) {
                            closed_count += 1;
                        }
                    }
                }
            }
        }

        if !recovery.suspended_processes.is_empty() {
            self.log(
                LogLevel::Success,
                "Processus",
                format!(
                    "{} processus d'arrière-plan suspendus (reprise instantanée à la fin).",
                    recovery.suspended_processes.len()
                ),
            );
        }
        if closed_count > 0 {
            self.log(
                LogLevel::Info,
                "Processus",
                format!(
                    "Signal WM_CLOSE envoyé à {} fenêtre(s) d'arrière-plan.",
                    closed_count
                ),
            );
        }

        // 6. PURGE INTELLIGENTE DE LA STANDBY LIST SI SOUS LE SEUIL
        if profile.purge_standby_list {
            let avail_mb = SystemMonitor::available_ram_mb();
            if avail_mb < self.config.standby_purge_threshold_mb {
                match win32_ops::purge_standby_list() {
                    Ok(()) => {
                        self.last_standby_purge = Some(Instant::now());
                        self.log(
                            LogLevel::Success,
                            "RAM",
                            format!(
                                "Standby List purgée (RAM libre {} Mo < seuil {} Mo).",
                                avail_mb, self.config.standby_purge_threshold_mb
                            ),
                        );
                    }
                    Err(e) => {
                        self.log(LogLevel::Warning, "RAM", e);
                    }
                }
            }
        }

        // 7. SERVICES WINDOWS NON ESSENTIELS + TÉLÉCHARGEMENTS RÉSEAU (BITS / DoSvc)
        let mut paused_services_count = 0usize;
        let service_rules = self.config.service_rules.clone();
        for svc in &service_rules {
            if !svc.enabled_for_pause {
                continue;
            }
            let should_pause = if svc.is_network_download_service {
                profile.pause_background_downloads
            } else {
                profile.pause_non_essential_services
            };
            if !should_pause {
                continue;
            }

            match win32_ops::stop_service_if_running(&svc.service_name) {
                Ok(true) => {
                    paused_services_count += 1;
                    recovery.stopped_services.push(ServiceRecoveryRecord {
                        service_name: svc.service_name.clone(),
                        was_running: true,
                        was_paused: false,
                    });
                }
                Ok(false) => {}
                Err(e) => {
                    if self.capabilities.is_admin {
                        self.log(LogLevel::Warning, "Services", e);
                    }
                }
            }
        }
        if paused_services_count > 0 {
            self.log(
                LogLevel::Success,
                "Services",
                format!(
                    "{} service(s) Windows non essentiel(s) mis en pause temporaire.",
                    paused_services_count
                ),
            );
        } else if !self.capabilities.is_admin && profile.pause_non_essential_services {
            self.log(
                LogLevel::Info,
                "Services",
                "Mode Standard : lancez en Administrateur pour mettre en pause les services Windows.",
            );
        }

        // 8. PRIORISATION RÉSEAU QoS DSCP 46
        let mut qos_active = false;
        if profile.enable_network_qos {
            if let Some(ref exe) = active_game_exe {
                let policy_name = "WinBoost_ActiveGame";
                match win32_ops::apply_qos_dscp_policy(policy_name, exe) {
                    Ok(()) => {
                        qos_active = true;
                        recovery
                            .created_qos_policy_names
                            .push(policy_name.to_string());
                        self.log(
                            LogLevel::Success,
                            "Réseau QoS",
                            format!("Stratégie QoS DSCP 46 (priorité haute) appliquée pour {}.", exe),
                        );
                    }
                    Err(e) => {
                        self.log(LogLevel::Warning, "Réseau QoS", e);
                    }
                }
            }
        }

        // 9. PERSISTANCE ATOMIQUE FINALE DU SNAPSHOT COMPLET
        if let Err(e) = recovery.save_atomic(&self.recovery_path) {
            self.log(
                LogLevel::Error,
                "Snapshot",
                format!("Erreur mise à jour recovery_state.json : {}", e),
            );
        }

        let ram_freed_mb = ram_freed_bytes as f64 / (1024.0 * 1024.0);
        if ram_freed_mb > 1.0 {
            self.log(
                LogLevel::Success,
                "RAM",
                format!("{:.1} Mo de Working Set libérés en toute sécurité.", ram_freed_mb),
            );
        }

        self.stats = BoostSessionStats {
            active: true,
            trigger_label,
            detected_game_name: detected_game.as_ref().map(|(g, _)| g.name.clone()),
            detected_game_pid: detected_game.as_ref().map(|(_, pid)| *pid),
            active_profile_name: profile_name,
            ram_freed_mb,
            suspended_processes_count: recovery.suspended_processes.len(),
            closed_processes_count: closed_count,
            paused_services_count,
            active_power_plan_label: active_power_label,
            qos_policy_active: qos_active,
            started_at: Some(Local::now()),
        };

        self.active_recovery = Some(recovery);
        self.refresh_capabilities();
    }

    fn maybe_purge_standby_during_session(&mut self) {
        let profile = self.config.active_profile();
        if !profile.purge_standby_list || !self.capabilities.is_admin {
            return;
        }
        if let Some(last) = self.last_standby_purge {
            if last.elapsed() < STANDBY_PURGE_COOLDOWN {
                return;
            }
        }
        let avail_mb = SystemMonitor::available_ram_mb();
        if avail_mb < self.config.standby_purge_threshold_mb {
            if win32_ops::purge_standby_list().is_ok() {
                self.last_standby_purge = Some(Instant::now());
                self.log(
                    LogLevel::Info,
                    "RAM",
                    format!(
                        "Nettoyage Standby List en cours de jeu (RAM libre {} Mo).",
                        avail_mb
                    ),
                );
            }
        }
    }

    /// Désactive le Boost et restaure intégralement l'état initial enregistré.
    pub fn deactivate_boost(&mut self) {
        self.triggered_by_auto_detect = false;
        self.tracked_game_instance = None;

        if let Some(recovery) = self.active_recovery.take() {
            self.restore_state_object(recovery);
        } else if let Ok(Some(disk_recovery)) = RecoveryState::detect_unrestored(&self.recovery_path)
        {
            self.restore_state_object(disk_recovery);
        }

        self.stats.active = false;
        self.stats.detected_game_name = None;
        self.stats.detected_game_pid = None;
        self.stats.suspended_processes_count = 0;
        self.stats.paused_services_count = 0;
        self.stats.qos_policy_active = false;
        self.stats.started_at = None;
        self.refresh_capabilities();
    }

    /// Restaure méthodiquement tous les éléments d'un `RecoveryState` dans l'ordre inverse.
    pub fn restore_state_object(&mut self, mut state: RecoveryState) {
        self.log(
            LogLevel::Info,
            "Restauration",
            format!("Restauration de la session {}...", state.session_id),
        );

        // 1. Reprendre les processus suspendus
        let mut resumed_count = 0usize;
        for proc_rec in &state.suspended_processes {
            match win32_ops::resume_process(proc_rec.pid, proc_rec.creation_time) {
                Ok(true) => resumed_count += 1,
                Ok(false) => {}
                Err(e) => self.log(
                    LogLevel::Warning,
                    "Restauration",
                    format!("Reprise {} (PID {}) : {}", proc_rec.exe_name, proc_rec.pid, e),
                ),
            }
        }
        if resumed_count > 0 {
            self.log(
                LogLevel::Success,
                "Restauration",
                format!("{} processus repris exactement où ils s'étaient arrêtés.", resumed_count),
            );
        }

        // 2. Restaurer priorités / affinités CPU
        for prio_rec in &state.modified_priorities {
            let _ = win32_ops::restore_process_cpu_optimization(
                prio_rec.pid,
                prio_rec.creation_time,
                prio_rec.original_priority_class,
                prio_rec.original_affinity_mask,
            );
        }

        // 3. Relancer les services Windows arrêtés (validation anti-tampering stricte)
        let mut restarted_services = 0usize;
        for svc in &state.stopped_services {
            if svc.was_running {
                if !crate::recovery::is_valid_service_name(&svc.service_name)
                    || crate::whitelist::is_critical_service(&svc.service_name)
                {
                    self.log(
                        LogLevel::Warning,
                        "Sécurité",
                        format!(
                            "Restauration service bloquée (nom invalide ou critique) : {}",
                            svc.service_name
                        ),
                    );
                    continue;
                }
                match win32_ops::start_service(&svc.service_name) {
                    Ok(()) => restarted_services += 1,
                    Err(e) => self.log(
                        LogLevel::Warning,
                        "Restauration",
                        format!("Relance service {} : {}", svc.service_name, e),
                    ),
                }
            }
        }
        if restarted_services > 0 {
            self.log(
                LogLevel::Success,
                "Restauration",
                format!("{} service(s) Windows relancé(s).", restarted_services),
            );
        }

        // 4. Supprimer les stratégies QoS temporaires (validation préfixe WinBoost_*)
        for policy in &state.created_qos_policy_names {
            if !crate::recovery::is_valid_qos_policy_name(policy) {
                self.log(
                    LogLevel::Warning,
                    "Sécurité",
                    format!("Stratégie QoS suspecte ignorée : {}", policy),
                );
                continue;
            }
            if let Err(e) = win32_ops::remove_qos_dscp_policy(policy) {
                self.log(LogLevel::Warning, "Restauration", e);
            }
        }

        // 5. Restaurer les clés registre modifiées (allowlist stricte uniquement)
        for reg in &state.registry_changes {
            if !crate::recovery::is_allowed_recovery_registry_record(reg) {
                self.log(
                    LogLevel::Warning,
                    "Sécurité",
                    format!(
                        "Entrée registre hors allowlist rejetée : {}\\{}\\{}",
                        reg.hive, reg.subkey, reg.value_name
                    ),
                );
                continue;
            }
            if let Err(e) = win32_ops::restore_registry_record(reg) {
                self.log(LogLevel::Warning, "Restauration", e);
            }
        }

        // 6. Restaurer le plan d'alimentation initial (validation GUID stricte)
        if let Some(ref guid) = state.original_power_plan_guid {
            if !crate::recovery::is_valid_power_guid(guid) {
                self.log(
                    LogLevel::Warning,
                    "Sécurité",
                    format!("GUID de plan d'alimentation invalide rejeté : {}", guid),
                );
            } else {
                match win32_ops::set_power_plan_guid(guid) {
                    Ok(()) => {
                        self.log(
                            LogLevel::Success,
                            "Restauration",
                            format!(
                                "Plan d'alimentation restauré : {}",
                                state
                                    .original_power_plan_name
                                    .as_deref()
                                    .unwrap_or(guid.as_str())
                            ),
                        );
                    }
                    Err(e) => {
                        self.log(
                            LogLevel::Warning,
                            "Restauration",
                            format!("Restauration plan d'alimentation : {}", e),
                        );
                    }
                }
            }
        }

        // 7. Nettoyer recovery_state.json
        if let Err(e) = state.mark_restored_and_cleanup(&self.recovery_path) {
            self.log(LogLevel::Warning, "Restauration", e);
        } else {
            self.log(
                LogLevel::Success,
                "Restauration",
                "Système 100 % restauré — recovery_state.json nettoyé.",
            );
        }
    }

    /// Sauvegarde manuelle d'un snapshot d'état sur demande (onglet Paramètres).
    pub fn save_manual_snapshot(&mut self) -> Result<String, String> {
        let mut snap = RecoveryState::new("Sauvegarde manuelle", self.config.active_global_profile.display_name());
        if let Some((guid, name)) = win32_ops::get_active_power_plan() {
            snap.original_power_plan_guid = Some(guid);
            snap.original_power_plan_name = Some(name);
        }
        snap.save_atomic(&self.recovery_path)?;
        let summary = snap.summary_line();
        self.log(
            LogLevel::Success,
            "Snapshot",
            format!("Snapshot manuel enregistré : {}", summary),
        );
        Ok(summary)
    }

    /// Change le profil global actif et sauvegarde la configuration.
    pub fn set_global_profile(&mut self, profile_id: ProfileId) {
        self.config.active_global_profile = profile_id.clone();
        let _ = self.config.save();
        self.log(
            LogLevel::Info,
            "Profil",
            format!("Profil global sélectionné : {}", profile_id.display_name()),
        );
    }

    /// Nettoyage RAM à la demande (Working Set uniquement, sans toucher aux processus protégés).
    pub fn quick_clean_ram(&mut self) -> f64 {
        let mut freed_bytes = 0u64;
        let procs = win32_ops::enumerate_processes(false);
        for p in procs {
            if p.pid <= 4 {
                continue;
            }
            if check_protection(&p.exe_name, &self.config.user_whitelist, None).is_some() {
                continue;
            }
            freed_bytes += win32_ops::trim_process_working_set(p.pid);
        }
        let mb = freed_bytes as f64 / (1024.0 * 1024.0);
        self.log(
            LogLevel::Success,
            "RAM",
            format!("Nettoyage rapide RAM : {:.1} Mo de Working Set libérés.", mb),
        );
        mb
    }
}
