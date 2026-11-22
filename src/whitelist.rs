/// Garde-fou absolu : Liste blanche (Whitelist) stricte et inviolable.
///
/// Cette liste empêche catégoriquement toute suspension, fermeture ou modification
/// destructrice des processus critiques Windows, des pilotes GPU/Audio, des logiciels
/// de périphériques essentiels et des systèmes Anti-Cheat.
/// Aucune règle utilisateur ne peut contourner `is_immutable_protected`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionReason {
    WindowsCore,
    GpuOrAudioDriver,
    PeripheralEssential,
    AntiCheat,
    SelfProcess,
    UserWhitelist,
}

impl ProtectionReason {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            ProtectionReason::WindowsCore => "Système Windows critique (inviolable)",
            ProtectionReason::GpuOrAudioDriver => "Pilote GPU / Audio (inviolable)",
            ProtectionReason::PeripheralEssential => "Périphérique essentiel (inviolable)",
            ProtectionReason::AntiCheat => "Système Anti-Cheat (inviolable)",
            ProtectionReason::SelfProcess => "WinBoost (auto-protection)",
            ProtectionReason::UserWhitelist => "Liste blanche utilisateur",
        }
    }
}

/// Processus critiques du noyau et du shell Windows (jamais suspendus ni fermés).
pub const WINDOWS_CORE_EXACT: &[&str] = &[
    "system",
    "system idle process",
    "idle",
    "registry",
    "memory compression",
    "secure system",
    "ntoskrnl.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "lsm.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
    "svchost.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "ctfmon.exe",
    "taskhostw.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "searchhost.exe",
    "applicationframehost.exe",
    "audiodg.exe",
    "spoolsv.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "mpdefendercoreservice.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "sgrmbroker.exe",
    "wudfhost.exe",
    "dashost.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "taskmgr.exe",
    "mmc.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "windowsterminal.exe",
    "openconsole.exe",
    "smartscreen.exe",
    "useroobebroker.exe",
    "lockapp.exe",
    "logonui.exe",
    "msiexec.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "consent.exe",
];

/// Pilotes graphiques, audio et gestionnaires matériels critiques.
pub const GPU_AUDIO_DRIVERS_EXACT: &[&str] = &[
    "nvdisplay.container.exe",
    "nvcontainer.exe",
    "nvtelemetrycontainer.exe",
    "nvidia share.exe",
    "nvidia overlay.exe",
    "nvsphelper64.exe",
    "nvcplui.exe",
    "radeonsoftware.exe",
    "amdrsserv.exe",
    "amdow.exe",
    "amddvr.exe",
    "atiesrxx.exe",
    "atieclxx.exe",
    "igfxem.exe",
    "igfxtray.exe",
    "igfxhk.exe",
    "igcctray.exe",
    "igcc.exe",
    "rtkauduservice64.exe",
    "ravcpl64.exe",
    "rtkngui64.exe",
    "nahimicservice.exe",
    "nahimicsvc64.exe",
    "dolbydax2api.exe",
    "voicemeeter.exe",
    "voicemeeterpro.exe",
    "voicemeeter8.exe",
    "voicemeeter8x64.exe",
    "equalizerapo.exe",
    "msi_afterburner.exe",
    "msiafterburner.exe",
    "rtss.exe",
    "rtsshooksloader64.exe",
];

/// Logiciels essentiels de périphériques (souris, clavier, casque, manette).
pub const PERIPHERALS_EXACT: &[&str] = &[
    "lghub_agent.exe",
    "lghub_updater.exe",
    "lghub.exe",
    "lcore.exe",
    "razer synapse 3.exe",
    "razercentralservice.exe",
    "razersynapseservice.exe",
    "rzsdkservice.exe",
    "gameManagerService.exe",
    "gamemanagerservice.exe",
    "icue.exe",
    "corsair.service.exe",
    "corsairservice.exe",
    "steelseriesgg.exe",
    "steelseriesengine3.exe",
    "steelseriessonar.exe",
    "ds4windows.exe",
    "wootility.exe",
    "synapse.exe",
    "ghub.exe",
    "elgatosoundcapture.exe",
    "streamdeck.exe",
    "wavelink.exe",
];

/// Systèmes Anti-Cheat (correspondance exacte ou par préfixe/mot-clé).
/// IMPORTANT : Ne JAMAIS suspendre, injecter ou toucher un processus Anti-Cheat,
/// sous peine de déconnexion, écran bleu (BSOD) ou sanction anti-triche.
pub const ANTICHEAT_PATTERNS: &[&str] = &[
    "vgc.exe",
    "vgtray.exe",
    "vanguard",
    "riotclientservices.exe",
    "easyanticheat",
    "eac_",
    "beservice",
    "bedaisy",
    "battleye",
    "ricochet",
    "faceitclient",
    "faceitservice",
    "eseaclient",
    "punkbuster",
    "pnkbstr",
    "gameguard",
    "gamemon",
    "nprotect",
    "xhunter",
    "xigncode",
    "mhyprot",
    "hoyokprotect",
    "ace-guard",
    "sguard",
    "sguardsvc",
    "equ8",
    "wellbia",
    "blackcipher",
    "nexongamesecurity",
    "anticheat",
    "anti-cheat",
    "eaanticheat",
    "javelin",
];

/// Vérifie si un nom de processus appartient à la liste blanche inviolable (impossible à désactiver).
pub fn immutable_protection_reason(exe_name: &str) -> Option<ProtectionReason> {
    let norm = normalize_exe_name(exe_name);
    if norm.is_empty() {
        return Some(ProtectionReason::WindowsCore);
    }

    if matches!(
        norm.as_str(),
        "winboost.exe" | "winboost" | "winboost-ui.exe" | "winboost-svc.exe"
    ) {
        return Some(ProtectionReason::SelfProcess);
    }

    if WINDOWS_CORE_EXACT.iter().any(|&p| p == norm) {
        return Some(ProtectionReason::WindowsCore);
    }

    if ANTICHEAT_PATTERNS.iter().any(|&pat| norm.contains(pat)) {
        return Some(ProtectionReason::AntiCheat);
    }

    if GPU_AUDIO_DRIVERS_EXACT.iter().any(|&p| p == norm) {
        return Some(ProtectionReason::GpuOrAudioDriver);
    }

    if PERIPHERALS_EXACT.iter().any(|&p| p == norm) {
        return Some(ProtectionReason::PeripheralEssential);
    }

    None
}

/// Vérifie si un processus est protégé (soit par la liste blanche inviolable, soit par la liste utilisateur).
pub fn check_protection(
    exe_name: &str,
    user_whitelist: &[String],
    active_game_exe: Option<&str>,
) -> Option<ProtectionReason> {
    if let Some(reason) = immutable_protection_reason(exe_name) {
        return Some(reason);
    }

    let norm = normalize_exe_name(exe_name);

    // Ne jamais suspendre ou fermer le jeu actif lui-même
    if let Some(game) = active_game_exe {
        if normalize_exe_name(game) == norm {
            return Some(ProtectionReason::UserWhitelist);
        }
    }

    if user_whitelist
        .iter()
        .any(|entry| normalize_exe_name(entry) == norm)
    {
        return Some(ProtectionReason::UserWhitelist);
    }

    None
}

/// Vérifie si un service Windows est critique et ne doit jamais être arrêté.
pub fn is_critical_service(service_name: &str) -> bool {
    let lower = service_name.trim().to_ascii_lowercase();
    const CRITICAL_SERVICES: &[&str] = &[
        "rpcss",
        "dcomlaunch",
        "lsm",
        "wininit",
        "eventlog",
        "plugplay",
        "power",
        "profsvc",
        "samss",
        "audiosrv",
        "audioendpointbuilder",
        "bfe",
        "mpssvc",
        "dhcp",
        "dnscache",
        "nsi",
        "netman",
        "nlasvc",
        "wlansvc",
        "windefend",
        "securityhealthservice",
        "vgc",
        "beservice",
        "easyanticheat",
        "easyanticheat_eos",
        "eaanticheatservice",
        "faceit",
        "cryptsvc",
        "gpsvc",
        "schedule",
        "themes",
        "uxsms",
    ];
    CRITICAL_SERVICES.contains(&lower.as_str())
        || ANTICHEAT_PATTERNS.iter().any(|pat| lower.contains(pat))
}

/// Liste lisible des entrées inviolables pour l'affichage dans l'interface utilisateur.
pub fn immutable_whitelist_summary() -> Vec<(&'static str, &'static str)> {
    let mut list = Vec::new();
    for &p in &[
        "System",
        "csrss.exe",
        "wininit.exe",
        "dwm.exe",
        "explorer.exe",
        "lsass.exe",
        "svchost.exe",
        "audiodg.exe",
        "MsMpEng.exe",
    ] {
        list.push((p, "Noyau & Shell Windows"));
    }
    for &p in &[
        "vgc.exe / vgtray.exe (Vanguard)",
        "EasyAntiCheat / EAC_EOS",
        "BEService / BEDaisy (BattlEye)",
        "Ricochet / EAAntiCheat / FaceIT",
    ] {
        list.push((p, "Anti-Cheat"));
    }
    for &p in &[
        "NVDisplay.Container.exe / RadeonSoftware.exe",
        "RtkAudUService64.exe / Nahimic / VoiceMeeter",
        "lghub_agent.exe / Razer Synapse / iCUE / SteelSeriesGG",
    ] {
        list.push((p, "Pilotes GPU / Audio & Périphériques"));
    }
    list
}

pub fn normalize_exe_name(name: &str) -> String {
    let trimmed = name.trim();
    let base = trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed);
    base.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_core_processes_are_inviolable() {
        for proc_name in [
            "System",
            "csrss.exe",
            "WININIT.EXE",
            "dwm.exe",
            "C:\\Windows\\explorer.exe",
            "lsass.exe",
            "svchost.exe",
            "audiodg.exe",
        ] {
            assert_eq!(
                immutable_protection_reason(proc_name),
                Some(ProtectionReason::WindowsCore),
                "{} doit être protégé comme processus Windows critique",
                proc_name
            );
        }
    }

    #[test]
    fn test_anticheat_processes_are_inviolable() {
        for ac in [
            "vgc.exe",
            "vgtray.exe",
            "EasyAntiCheat.exe",
            "EasyAntiCheat_EOS.exe",
            "BEService.exe",
            "BEDaisy.exe",
            "Ricochet.exe",
            "EAAntiCheat.GameService.exe",
            "FACEITService.exe",
        ] {
            assert_eq!(
                immutable_protection_reason(ac),
                Some(ProtectionReason::AntiCheat),
                "{} doit être protégé comme Anti-Cheat",
                ac
            );
        }
    }

    #[test]
    fn test_drivers_and_peripherals_protected() {
        assert_eq!(
            immutable_protection_reason("NVDisplay.Container.exe"),
            Some(ProtectionReason::GpuOrAudioDriver)
        );
        assert_eq!(
            immutable_protection_reason("lghub_agent.exe"),
            Some(ProtectionReason::PeripheralEssential)
        );
    }

    #[test]
    fn test_non_critical_app_allowed_unless_user_whitelisted() {
        let user_wl = vec!["discord.exe".to_string()];
        assert_eq!(check_protection("chrome.exe", &user_wl, Some("cs2.exe")), None);
        assert_eq!(
            check_protection("Discord.exe", &user_wl, Some("cs2.exe")),
            Some(ProtectionReason::UserWhitelist)
        );
        // Le jeu actif est toujours protégé
        assert_eq!(
            check_protection("cs2.exe", &user_wl, Some("cs2.exe")),
            Some(ProtectionReason::UserWhitelist)
        );
    }

    #[test]
    fn test_self_processes_are_inviolable() {
        for exe in ["winboost.exe", "winboost-ui.exe", "winboost-svc.exe", "WinBoost-UI.EXE"] {
            assert_eq!(
                immutable_protection_reason(exe),
                Some(ProtectionReason::SelfProcess),
                "{} doit être auto-protégé",
                exe
            );
        }
    }

    #[test]
    fn test_critical_services_cannot_be_stopped() {
        assert!(is_critical_service("RpcSs"));
        assert!(is_critical_service("AudioSrv"));
        assert!(is_critical_service("vgc"));
        assert!(is_critical_service("BEService"));
        assert!(!is_critical_service("WSearch"));
        assert!(!is_critical_service("BITS"));
    }
}
