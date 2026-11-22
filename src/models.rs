use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Identifiant des profils globaux prédéfinis ou personnalisés.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfileId {
    Balanced,
    Competitive,
    SilentLaptop,
    Custom(String),
}

impl ProfileId {
    pub fn display_name(&self) -> String {
        match self {
            ProfileId::Balanced => "Équilibré".to_string(),
            ProfileId::Competitive => "Compétitif / Max FPS".to_string(),
            ProfileId::SilentLaptop => "Silencieux / Laptop".to_string(),
            ProfileId::Custom(name) => name.clone(),
        }
    }

    #[allow(dead_code)]
    pub fn key(&self) -> String {
        match self {
            ProfileId::Balanced => "balanced".to_string(),
            ProfileId::Competitive => "competitive".to_string(),
            ProfileId::SilentLaptop => "silent_laptop".to_string(),
            ProfileId::Custom(name) => format!("custom:{}", name),
        }
    }
}

/// Priorité CPU sécurisée pour le processus du jeu.
/// NOTE DE SÉCURITÉ : `REALTIME_PRIORITY_CLASS` est volontairement absent afin
/// d'empêcher tout gel du noyau ou des pilotes d'entrée Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeCpuPriority {
    Normal,
    AboveNormal,
    High,
}

impl SafeCpuPriority {
    pub fn label(&self) -> &'static str {
        match self {
            SafeCpuPriority::Normal => "Normale",
            SafeCpuPriority::AboveNormal => "Supérieure à la normale",
            SafeCpuPriority::High => "Haute (High)",
        }
    }

    pub fn to_win32_class(&self) -> u32 {
        match self {
            SafeCpuPriority::Normal => 0x0000_0020,      // NORMAL_PRIORITY_CLASS
            SafeCpuPriority::AboveNormal => 0x0000_8000, // ABOVE_NORMAL_PRIORITY_CLASS
            SafeCpuPriority::High => 0x0000_0080,        // HIGH_PRIORITY_CLASS
        }
    }
}

/// Plan d'alimentation cible pendant une session de boost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerPlanTarget {
    KeepCurrent,
    Balanced,
    HighPerformance,
    UltimatePerformance,
}

impl PowerPlanTarget {
    pub fn label(&self) -> &'static str {
        match self {
            PowerPlanTarget::KeepCurrent => "Conserver le plan actuel",
            PowerPlanTarget::Balanced => "Usage normal (Équilibré)",
            PowerPlanTarget::HighPerformance => "Performances élevées",
            PowerPlanTarget::UltimatePerformance => "Performances optimales (Ultimate)",
        }
    }
}

/// Action applicable à un processus d'arrière-plan non critique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessAction {
    Ignore,
    Suspend,
    CloseGracefully,
}

impl ProcessAction {
    pub fn label(&self) -> &'static str {
        match self {
            ProcessAction::Ignore => "Ignorer",
            ProcessAction::Suspend => "Suspendre (réversible)",
            ProcessAction::CloseGracefully => "Fermer proprement",
        }
    }
}

/// Profil complet d'optimisation gaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoostProfile {
    pub id: ProfileId,
    pub description: String,
    pub power_plan: PowerPlanTarget,
    pub game_cpu_priority: SafeCpuPriority,
    /// Évite le cœur logique 0 (souvent sollicité par les interruptions système/DPC).
    pub avoid_core_0: bool,
    /// Nettoie le Working Set des processus non critiques en arrière-plan.
    pub trim_working_sets: bool,
    /// Purge la Standby List si la RAM libre passe sous le seuil configuré (Admin requis).
    pub purge_standby_list: bool,
    /// Active temporairement le Mode Jeu Windows (restauré après).
    pub enable_game_mode: bool,
    /// Suspend agressivement les navigateurs et launchers secondaires.
    pub suspend_browsers_and_launchers: bool,
    /// Suspend également les applis de communication (ex. Discord, Spotify) si non protégées.
    pub suspend_comm_apps: bool,
    /// Met en pause les services Windows non essentiels sélectionnés.
    pub pause_non_essential_services: bool,
    /// Active la priorisation réseau QoS DSCP 46 pour le jeu et pause BITS/DoSvc.
    pub enable_network_qos: bool,
    pub pause_background_downloads: bool,
}

impl BoostProfile {
    pub fn built_in_profiles() -> Vec<BoostProfile> {
        vec![
            BoostProfile {
                id: ProfileId::Balanced,
                description: "Optimisations douces et sûres : garde Discord et les navigateurs actifs tout en libérant la RAM et en priorisant le jeu.".to_string(),
                power_plan: PowerPlanTarget::HighPerformance,
                game_cpu_priority: SafeCpuPriority::High,
                avoid_core_0: false,
                trim_working_sets: true,
                purge_standby_list: false,
                enable_game_mode: true,
                suspend_browsers_and_launchers: false,
                suspend_comm_apps: false,
                pause_non_essential_services: true,
                enable_network_qos: true,
                pause_background_downloads: true,
            },
            BoostProfile {
                id: ProfileId::Competitive,
                description: "Performance maximale : alimentation Ultimate, priorité Haute, exclusion Core 0, suspension de l'arrière-plan, QoS DSCP 46 et purge RAM intelligente.".to_string(),
                power_plan: PowerPlanTarget::UltimatePerformance,
                game_cpu_priority: SafeCpuPriority::High,
                avoid_core_0: true,
                trim_working_sets: true,
                purge_standby_list: true,
                enable_game_mode: true,
                suspend_browsers_and_launchers: true,
                suspend_comm_apps: false,
                pause_non_essential_services: true,
                enable_network_qos: true,
                pause_background_downloads: true,
            },
            BoostProfile {
                id: ProfileId::SilentLaptop,
                description: "Idéal PC portable : limite les pics thermiques et le bruit ventilateur en gardant le plan Équilibré tout en stabilisant les frametimes.".to_string(),
                power_plan: PowerPlanTarget::Balanced,
                game_cpu_priority: SafeCpuPriority::AboveNormal,
                avoid_core_0: false,
                trim_working_sets: true,
                purge_standby_list: false,
                enable_game_mode: true,
                suspend_browsers_and_launchers: true,
                suspend_comm_apps: false,
                pause_non_essential_services: true,
                enable_network_qos: true,
                pause_background_downloads: true,
            },
        ]
    }
}

/// Règle personnalisée sur un processus connu en arrière-plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRule {
    pub exe_name: String,
    pub category: String,
    pub action: ProcessAction,
    /// Si true, n'est appliqué qu'en profil agressif (sauf si action explicite choisie).
    pub is_browser_or_launcher: bool,
    pub is_comm_app: bool,
}

/// Règle sur un service Windows non essentiel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRule {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub enabled_for_pause: bool,
    pub is_network_download_service: bool,
}

/// Jeu configuré pour la détection automatique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameEntry {
    pub name: String,
    /// Nom d'exécutable en minuscules (ex. "cs2.exe").
    pub exe_name: String,
    /// Chemin complet optionnel si ajouté manuellement.
    pub full_path: Option<String>,
    pub assigned_profile: ProfileId,
    /// Surcharges optionnelles par jeu.
    pub override_avoid_core_0: Option<bool>,
    pub override_priority: Option<SafeCpuPriority>,
    pub override_network_qos: Option<bool>,
    pub auto_boost_enabled: bool,
    pub is_custom: bool,
}

impl GameEntry {
    /// Résout le profil effectif pour ce jeu en appliquant ses surcharges éventuelles.
    pub fn resolve_profile(&self, profiles: &[BoostProfile]) -> BoostProfile {
        let mut base = profiles
            .iter()
            .find(|p| p.id == self.assigned_profile)
            .cloned()
            .unwrap_or_else(|| BoostProfile::built_in_profiles()[0].clone());

        if let Some(avoid) = self.override_avoid_core_0 {
            base.avoid_core_0 = avoid;
        }
        if let Some(prio) = self.override_priority {
            base.game_cpu_priority = prio;
        }
        if let Some(qos) = self.override_network_qos {
            base.enable_network_qos = qos;
        }
        base
    }
}

/// Niveau de gravité d'un événement du journal interne.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Local>,
    pub level: LogLevel,
    pub category: String,
    pub message: String,
}

/// Statistiques résumées d'une session de boost active ou récente.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoostSessionStats {
    pub active: bool,
    pub trigger_label: String,
    pub detected_game_name: Option<String>,
    pub detected_game_pid: Option<u32>,
    pub active_profile_name: String,
    pub ram_freed_mb: f64,
    pub suspended_processes_count: usize,
    pub closed_processes_count: usize,
    pub paused_services_count: usize,
    pub active_power_plan_label: String,
    pub qos_policy_active: bool,
    pub started_at: Option<DateTime<Local>>,
}

/// Résultat d'un test de latence réseau (ICMP Ping).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub target_name: String,
    pub host: String,
    pub resolved_ip: String,
    pub sent: u32,
    pub received: u32,
    pub loss_percent: f32,
    pub min_ms: f32,
    pub avg_ms: f32,
    pub max_ms: f32,
    pub jitter_ms: f32,
    pub timestamp: DateTime<Local>,
    pub error: Option<String>,
}

/// État système Windows détecté (Mode Jeu, HAGS, droits Admin).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemCapabilities {
    pub is_admin: bool,
    pub game_mode_enabled: Option<bool>,
    pub hags_enabled: Option<bool>,
    #[allow(dead_code)]
    pub active_power_plan_guid: Option<String>,
    pub active_power_plan_name: String,
    pub logical_cpu_count: usize,
    pub gpu_name: String,
    pub os_label: String,
}

/// Métriques temps réel affichées dans l'onglet Monitoring (en pause quand aucun client UI).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f32,
    pub ram_used_gb: f32,
    pub ram_free_gb: f32,
    pub ram_total_gb: f32,
    pub ram_usage_percent: f32,
    pub gpu_usage_percent: Option<f32>,
    pub gpu_vram_used_mb: Option<u64>,
    pub gpu_vram_total_mb: Option<u64>,
    pub gpu_temp_c: Option<f32>,
    pub cpu_temp_c: Option<f32>,
    pub net_latency_ms: Option<f32>,
    pub app_ram_mb: f32,
}

/// Informations légères sur un processus en cours d'exécution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningProcessInfo {
    pub pid: u32,
    pub name: String,
    #[allow(dead_code)]
    pub full_path: Option<String>,
    pub ram_mb: f64,
    #[allow(dead_code)]
    pub creation_time: u64,
    pub is_immutable_protected: bool,
    pub is_user_whitelisted: bool,
    pub is_suspended_by_us: bool,
}

/// Configuration persistante de l'application stockée localement en JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub auto_boost_enabled: bool,
    pub poll_interval_ms: u64,
    pub active_global_profile: ProfileId,
    pub launch_with_windows: bool,
    pub start_minimized_to_tray: bool,
    pub minimize_to_tray_on_close: bool,
    pub toast_notifications_enabled: bool,
    pub auto_crash_recovery: bool,
    /// Seuil de RAM libre (en Mo) sous lequel la purge de Standby List est autorisée.
    pub standby_purge_threshold_mb: u64,
    /// Dossiers de jeux surveillés (tout .exe lancé depuis ces dossiers déclenche Auto-Boost).
    pub watched_game_folders: Vec<String>,
    pub profiles: Vec<BoostProfile>,
    pub games: Vec<GameEntry>,
    pub process_rules: Vec<ProcessRule>,
    pub service_rules: Vec<ServiceRule>,
    pub user_whitelist: Vec<String>,
    pub ping_custom_host: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_boost_enabled: true,
            poll_interval_ms: 2500,
            active_global_profile: ProfileId::Balanced,
            launch_with_windows: false,
            start_minimized_to_tray: false,
            minimize_to_tray_on_close: true,
            toast_notifications_enabled: true,
            auto_crash_recovery: true,
            standby_purge_threshold_mb: 2048,
            watched_game_folders: vec![],
            profiles: BoostProfile::built_in_profiles(),
            games: default_game_database(),
            process_rules: default_process_rules(),
            service_rules: default_service_rules(),
            user_whitelist: vec!["discord.exe".to_string(), "obs64.exe".to_string()],
            ping_custom_host: "1.1.1.1".to_string(),
        }
    }
}

impl AppConfig {
    pub fn data_dir() -> PathBuf {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let dir = PathBuf::from(local_app_data).join("WinBoost");
            if std::fs::create_dir_all(&dir).is_ok() {
                return dir;
            }
        }
        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("winboost_data");
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    }

    pub fn config_path() -> PathBuf {
        Self::data_dir().join("config.json")
    }

    pub fn load_or_default() -> Self {
        let path = Self::config_path();
        Self::load_from_path(&path).unwrap_or_default()
    }

    pub fn load_from_path(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let mut cfg: AppConfig = serde_json::from_str(&content).ok()?;
        // Garantir que les 3 profils prédéfinis existent toujours
        for builtin in BoostProfile::built_in_profiles() {
            if !cfg.profiles.iter().any(|p| p.id == builtin.id) {
                cfg.profiles.push(builtin);
            }
        }
        Some(cfg)
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to_path(&Self::config_path())
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_profile(&self, id: &ProfileId) -> BoostProfile {
        self.profiles
            .iter()
            .find(|p| &p.id == id)
            .cloned()
            .unwrap_or_else(|| BoostProfile::built_in_profiles()[0].clone())
    }

    pub fn active_profile(&self) -> BoostProfile {
        self.get_profile(&self.active_global_profile)
    }

    /// Cherche un jeu correspondant à un processus en cours (par nom d'exe ou dossier surveillé).
    pub fn match_game_process(&self, exe_name: &str, full_path: Option<&str>) -> Option<GameEntry> {
        let lower_exe = exe_name.to_ascii_lowercase();

        // 1. Correspondance exacte dans la bibliothèque de jeux
        if let Some(entry) = self
            .games
            .iter()
            .find(|g| g.auto_boost_enabled && g.exe_name.to_ascii_lowercase() == lower_exe)
        {
            return Some(entry.clone());
        }

        // 2. Correspondance par dossier de jeux surveillé
        if let Some(path_str) = full_path {
            let lower_path = path_str.replace('/', "\\").to_ascii_lowercase();
            // Ignorer les installateurs, launchers et crash reporters dans les dossiers de jeux
            let ignored_substrings = [
                "unins",
                "setup",
                "redist",
                "vcredist",
                "dxsetup",
                "crashreporter",
                "crashhandler",
                "ue4prereq",
                "easyanticheat",
                "battleye",
                "launcher",
            ];
            if ignored_substrings.iter().any(|s| lower_exe.contains(s)) {
                return None;
            }

            for folder in &self.watched_game_folders {
                let norm_folder = folder
                    .trim()
                    .trim_end_matches(['\\', '/'])
                    .replace('/', "\\")
                    .to_ascii_lowercase();
                if !norm_folder.is_empty() && lower_path.starts_with(&format!("{}\\", norm_folder))
                {
                    let display = exe_name
                        .strip_suffix(".exe")
                        .or_else(|| exe_name.strip_suffix(".EXE"))
                        .unwrap_or(exe_name)
                        .to_string();
                    return Some(GameEntry {
                        name: format!("{} (Dossier surveillé)", display),
                        exe_name: lower_exe,
                        full_path: Some(path_str.to_string()),
                        assigned_profile: self.active_global_profile.clone(),
                        override_avoid_core_0: None,
                        override_priority: None,
                        override_network_qos: None,
                        auto_boost_enabled: true,
                        is_custom: true,
                    });
                }
            }
        }

        None
    }

    pub fn process_rule_map(&self) -> HashMap<String, ProcessRule> {
        self.process_rules
            .iter()
            .map(|r| (r.exe_name.to_ascii_lowercase(), r.clone()))
            .collect()
    }
}

/// Base intégrée de jeux populaires détectés automatiquement.
pub fn default_game_database() -> Vec<GameEntry> {
    let entries: &[(&str, &str, ProfileId)] = &[
        ("Counter-Strike 2", "cs2.exe", ProfileId::Competitive),
        (
            "Valorant",
            "valorant-win64-shipping.exe",
            ProfileId::Competitive,
        ),
        (
            "Fortnite",
            "fortniteclient-win64-shipping.exe",
            ProfileId::Competitive,
        ),
        ("Apex Legends", "r5apex.exe", ProfileId::Competitive),
        ("Apex Legends (DX12)", "r5apex_dx12.exe", ProfileId::Competitive),
        ("Call of Duty", "cod.exe", ProfileId::Competitive),
        (
            "League of Legends",
            "league of legends.exe",
            ProfileId::Competitive,
        ),
        ("Dota 2", "dota2.exe", ProfileId::Competitive),
        ("Overwatch 2", "overwatch.exe", ProfileId::Competitive),
        ("Rainbow Six Siege", "rainbowsix.exe", ProfileId::Competitive),
        ("Rocket League", "rocketleague.exe", ProfileId::Competitive),
        ("PUBG: Battlegrounds", "tslgame.exe", ProfileId::Competitive),
        (
            "Marvel Rivals",
            "marvel-win64-shipping.exe",
            ProfileId::Competitive,
        ),
        (
            "Escape from Tarkov",
            "escapefromtarkov.exe",
            ProfileId::Competitive,
        ),
        ("Rust", "rustclient.exe", ProfileId::Competitive),
        ("Cyberpunk 2077", "cyberpunk2077.exe", ProfileId::Balanced),
        ("Elden Ring", "eldenring.exe", ProfileId::Balanced),
        ("Grand Theft Auto V", "gta5.exe", ProfileId::Balanced),
        ("Red Dead Redemption 2", "rdr2.exe", ProfileId::Balanced),
        ("The Witcher 3", "witcher3.exe", ProfileId::Balanced),
        ("Baldur's Gate 3", "bg3.exe", ProfileId::Balanced),
        ("Baldur's Gate 3 (DX11)", "bg3_dx11.exe", ProfileId::Balanced),
        ("Helldivers 2", "helldivers2.exe", ProfileId::Balanced),
        (
            "Palworld",
            "palworld-win64-shipping.exe",
            ProfileId::Balanced,
        ),
        ("Starfield", "starfield.exe", ProfileId::Balanced),
        ("Destiny 2", "destiny2.exe", ProfileId::Competitive),
        ("Warframe", "warframe.x64.exe", ProfileId::Balanced),
        ("Forza Horizon 5", "forzahorizon5.exe", ProfileId::Balanced),
        ("EA SPORTS FC 25", "fc25.exe", ProfileId::Balanced),
        ("Diablo IV", "diablo iv.exe", ProfileId::Balanced),
        ("Path of Exile 2", "pathofexilesteam.exe", ProfileId::Balanced),
        ("World of Warcraft", "wow.exe", ProfileId::Balanced),
        ("Final Fantasy XIV", "ffxiv_dx11.exe", ProfileId::Balanced),
        ("Genshin Impact", "genshinimpact.exe", ProfileId::Balanced),
        ("Minecraft (Bedrock)", "minecraft.windows.exe", ProfileId::Balanced),
        ("DayZ", "dayz_x64.exe", ProfileId::Competitive),
        ("Battlefield 2042", "bf2042.exe", ProfileId::Competitive),
        (
            "Dead by Daylight",
            "deadbydaylight-win64-shipping.exe",
            ProfileId::Balanced,
        ),
    ];

    entries
        .iter()
        .map(|(name, exe, profile)| GameEntry {
            name: (*name).to_string(),
            exe_name: (*exe).to_string(),
            full_path: None,
            assigned_profile: profile.clone(),
            override_avoid_core_0: None,
            override_priority: None,
            override_network_qos: None,
            auto_boost_enabled: true,
            is_custom: false,
        })
        .collect()
}

/// Règles par défaut pour les applications d'arrière-plan gourmandes et non essentielles.
pub fn default_process_rules() -> Vec<ProcessRule> {
    let items: &[(&str, &str, ProcessAction, bool, bool)] = &[
        ("chrome.exe", "Navigateur", ProcessAction::Suspend, true, false),
        ("msedge.exe", "Navigateur", ProcessAction::Suspend, true, false),
        ("firefox.exe", "Navigateur", ProcessAction::Suspend, true, false),
        ("brave.exe", "Navigateur", ProcessAction::Suspend, true, false),
        ("opera.exe", "Navigateur", ProcessAction::Suspend, true, false),
        ("onedrive.exe", "Cloud / Sync", ProcessAction::Suspend, false, false),
        ("dropbox.exe", "Cloud / Sync", ProcessAction::Suspend, false, false),
        ("googledrivefs.exe", "Cloud / Sync", ProcessAction::Suspend, false, false),
        ("epicgameslauncher.exe", "Launcher secondaire", ProcessAction::Suspend, true, false),
        ("upc.exe", "Launcher secondaire", ProcessAction::Suspend, true, false),
        ("eadesktop.exe", "Launcher secondaire", ProcessAction::Suspend, true, false),
        ("battle.net.exe", "Launcher secondaire", ProcessAction::Suspend, true, false),
        ("galaxyclient.exe", "Launcher secondaire", ProcessAction::Suspend, true, false),
        ("adobe desktop service.exe", "Mises à jour / Fond", ProcessAction::Suspend, false, false),
        ("ccxprocess.exe", "Mises à jour / Fond", ProcessAction::Suspend, false, false),
        ("creative cloud.exe", "Mises à jour / Fond", ProcessAction::Suspend, false, false),
        ("ms-teams.exe", "Communication", ProcessAction::Suspend, false, true),
        ("teams.exe", "Communication", ProcessAction::Suspend, false, true),
        ("slack.exe", "Communication", ProcessAction::Suspend, false, true),
        ("spotify.exe", "Média", ProcessAction::Ignore, false, true),
        ("discord.exe", "Communication", ProcessAction::Ignore, false, true),
        ("widgets.exe", "Widgets Windows", ProcessAction::Suspend, false, false),
        ("phoneexperiencehost.exe", "Mobile connecté", ProcessAction::Suspend, false, false),
        ("wallpaper32.exe", "Fond animé", ProcessAction::Suspend, false, false),
        ("wallpaper64.exe", "Fond animé", ProcessAction::Suspend, false, false),
    ];

    items
        .iter()
        .map(|(exe, cat, action, browser, comm)| ProcessRule {
            exe_name: (*exe).to_string(),
            category: (*cat).to_string(),
            action: *action,
            is_browser_or_launcher: *browser,
            is_comm_app: *comm,
        })
        .collect()
}

/// Liste prédéfinie de services Windows non essentiels pouvant être mis en pause temporairement.
pub fn default_service_rules() -> Vec<ServiceRule> {
    vec![
        ServiceRule {
            service_name: "WSearch".to_string(),
            display_name: "Windows Search (Indexation)".to_string(),
            description: "Évite les accès disque/CPU d'indexation pendant les parties.".to_string(),
            enabled_for_pause: true,
            is_network_download_service: false,
        },
        ServiceRule {
            service_name: "DiagTrack".to_string(),
            display_name: "Expériences des utilisateurs et télémétrie".to_string(),
            description: "Met en pause la collecte diagnostique en arrière-plan.".to_string(),
            enabled_for_pause: true,
            is_network_download_service: false,
        },
        ServiceRule {
            service_name: "SysMain".to_string(),
            display_name: "SysMain (Superfetch)".to_string(),
            description: "Préchargement mémoire/disque (optionnel, utile si pics disque).".to_string(),
            enabled_for_pause: false,
            is_network_download_service: false,
        },
        ServiceRule {
            service_name: "Spooler".to_string(),
            display_name: "Spouleur d'impression".to_string(),
            description: "Mis en pause uniquement si activé et aucune impression en cours.".to_string(),
            enabled_for_pause: false,
            is_network_download_service: false,
        },
        ServiceRule {
            service_name: "BITS".to_string(),
            display_name: "Transfert intelligent en arrière-plan (BITS)".to_string(),
            description: "Empêche les téléchargements Windows de provoquer des pics de ping.".to_string(),
            enabled_for_pause: true,
            is_network_download_service: true,
        },
        ServiceRule {
            service_name: "DoSvc".to_string(),
            display_name: "Optimisation de livraison Windows Update".to_string(),
            description: "Suspend le partage/téléchargement P2P Windows Update pendant le jeu.".to_string(),
            enabled_for_pause: true,
            is_network_download_service: true,
        },
        ServiceRule {
            service_name: "WerSvc".to_string(),
            display_name: "Rapport d'erreurs Windows".to_string(),
            description: "Désactive temporairement la collecte de rapports de crash en fond.".to_string(),
            enabled_for_pause: false,
            is_network_download_service: false,
        },
        ServiceRule {
            service_name: "MapsBroker".to_string(),
            display_name: "Gestionnaire de cartes téléchargées".to_string(),
            description: "Service de synchronisation de cartes hors-ligne non requis en jeu.".to_string(),
            enabled_for_pause: false,
            is_network_download_service: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_profile_resolution_and_overrides() {
        let profiles = BoostProfile::built_in_profiles();
        let game = GameEntry {
            name: "Mon FPS".to_string(),
            exe_name: "myfps.exe".to_string(),
            full_path: None,
            assigned_profile: ProfileId::Balanced,
            override_avoid_core_0: Some(true),
            override_priority: Some(SafeCpuPriority::High),
            override_network_qos: Some(false),
            auto_boost_enabled: true,
            is_custom: true,
        };

        let resolved = game.resolve_profile(&profiles);
        assert_eq!(resolved.id, ProfileId::Balanced);
        assert!(resolved.avoid_core_0);
        assert_eq!(resolved.game_cpu_priority, SafeCpuPriority::High);
        assert!(!resolved.enable_network_qos);
    }

    #[test]
    fn test_safe_cpu_priority_never_realtime() {
        let realtime_class: u32 = 0x0000_0100;
        for prio in [
            SafeCpuPriority::Normal,
            SafeCpuPriority::AboveNormal,
            SafeCpuPriority::High,
        ] {
            assert_ne!(prio.to_win32_class(), realtime_class);
        }
    }

    #[test]
    fn test_game_matching_by_exe_and_watched_folder() {
        let mut cfg = AppConfig::default();
        cfg.watched_game_folders.push(r"D:\Games\Indie".to_string());

        let m1 = cfg.match_game_process("CS2.EXE", None);
        assert!(m1.is_some());
        assert_eq!(m1.unwrap().assigned_profile, ProfileId::Competitive);

        let m2 = cfg.match_game_process("hades2.exe", Some(r"D:\Games\Indie\Hades2\hades2.exe"));
        assert!(m2.is_some());
        assert_eq!(m2.unwrap().exe_name, "hades2.exe");

        // Les installateurs/launchers dans un dossier de jeu ne doivent pas déclencher le boost
        let m3 = cfg.match_game_process("unins000.exe", Some(r"D:\Games\Indie\Hades2\unins000.exe"));
        assert!(m3.is_none());
    }
}
