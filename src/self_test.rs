//! Auto-test fonctionnel bout-en-bout (`--self-test <file.json>`).
//!
//! Exerce et mesure directement depuis l'état réel de l'application les 3 étapes clés :
//! - `move` : bascule des profils, détection jeux/dossiers & IPC Named Pipe (`\\.\pipe\WinBoost`)
//! - `act`  : whitelist inviolable, validation anti-tampering, `MoveFileExW`, Ping IPv4/IPv6, Nettoyage PC
//! - `hud`  : initialisation Direct2D + DirectWrite, télémétrie CPU/RAM/processus, empreinte mémoire

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::cleaner;
use crate::engine::BoostEngine;
use crate::ipc::{
    handle_ipc_request, run_pipe_server_loop, IpcClient, IpcRequest, IpcResponse, ServiceBackend,
};
use crate::models::{AppConfig, ProcessAction, ProfileId, SafeCpuPriority};
use crate::monitoring::SystemMonitor;
use crate::recovery::{
    is_allowed_recovery_registry_record, is_valid_qos_policy_name, RecoveryState,
    RegistryRecoveryRecord, ServiceRecoveryRecord, SuspendedProcessRecord,
};
use crate::ui;
use crate::whitelist::{
    check_protection, immutable_protection_reason, is_critical_service, ProtectionReason,
};
use crate::win32_ops;

#[derive(Debug, Serialize)]
struct SelfTestStep {
    step: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct SelfTestReport {
    version: u32,
    steps: Vec<SelfTestStep>,
}

pub fn run_self_test(output_path: &Path) -> Result<bool, String> {
    let mut steps = Vec::new();

    // 1. `move` : profils, détection auto jeux/dossiers + boucle IPC Named Pipe sécurisée
    let temp_rec_path = std::env::temp_dir().join(format!(
        "winboost_selftest_{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&temp_rec_path);

    let mut cfg = AppConfig::default();
    cfg.watched_game_folders.push(r"D:\Games\Library".to_string());
    let mut engine = BoostEngine::new(cfg, temp_rec_path.clone());

    let initial_prof = engine.config.active_global_profile.clone();
    engine.config.active_global_profile = ProfileId::Competitive;
    let moved_to_comp = engine.config.active_profile().id == ProfileId::Competitive;
    engine.config.active_global_profile = ProfileId::SilentLaptop;
    let moved_to_silent = engine.config.active_profile().id == ProfileId::SilentLaptop;
    engine.config.active_global_profile = initial_prof;

    let detected_exe = engine.config.match_game_process("cs2.exe", None);
    let detected_folder = engine.config.match_game_process(
        "customgame.exe",
        Some(r"D:\Games\Library\Custom\customgame.exe"),
    );
    let affinity_ok = win32_ops::compute_safe_affinity_mask(0xFF, true) == Some(0xFE);
    let prio_safe = SafeCpuPriority::High.to_win32_class() == 0x80
        && SafeCpuPriority::High.to_win32_class() != 0x100;
    let clean_cats = cleaner::default_clean_categories();

    // Test réel Named Pipe IPC avec ACL SDDL stricte
    let pipe_name = format!(r"\\.\pipe\WinBoost_SelfTest_{}", std::process::id());
    let pipe_backend = Arc::new(Mutex::new(ServiceBackend::new(
        AppConfig::default(),
        temp_rec_path.clone(),
    )));
    let srv_b = Arc::clone(&pipe_backend);
    let srv_p = pipe_name.clone();
    let srv_thread = std::thread::spawn(move || run_pipe_server_loop(srv_p, srv_b));
    std::thread::sleep(Duration::from_millis(60));

    let ipc_client = IpcClient::new(&pipe_name);
    let ipc_ping_ok = matches!(ipc_client.send(&IpcRequest::Ping), Ok(IpcResponse::Pong { .. }));
    let ipc_state_ok = matches!(
        ipc_client.send(&IpcRequest::GetState {
            include_processes: false
        }),
        Ok(IpcResponse::State { .. })
    );
    let _ = ipc_client.send(&IpcRequest::ShutdownService);
    let _ = srv_thread.join();

    let move_passed = moved_to_comp
        && moved_to_silent
        && detected_exe.is_some()
        && detected_folder.is_some()
        && affinity_ok
        && prio_safe
        && clean_cats.len() == 6
        && ipc_ping_ok
        && ipc_state_ok;

    steps.push(SelfTestStep {
        step: "move".to_string(),
        passed: move_passed,
        detail: format!(
            "3 profils OK, {} jeux, {} catégories nettoyage, Named Pipe IPC sécurisé={}",
            engine.config.games.len(),
            clean_cats.len(),
            ipc_ping_ok && ipc_state_ok
        ),
    });

    // 2. `act` : whitelist inviolable + validation serveur IPC + MoveFileExW + Ping IPv4/IPv6
    let core_ok = immutable_protection_reason("csrss.exe") == Some(ProtectionReason::WindowsCore)
        && immutable_protection_reason("dwm.exe") == Some(ProtectionReason::WindowsCore)
        && immutable_protection_reason("explorer.exe") == Some(ProtectionReason::WindowsCore)
        && immutable_protection_reason("lsass.exe") == Some(ProtectionReason::WindowsCore);
    let anticheat_ok = immutable_protection_reason("vgc.exe") == Some(ProtectionReason::AntiCheat)
        && immutable_protection_reason("EasyAntiCheat_EOS.exe") == Some(ProtectionReason::AntiCheat)
        && immutable_protection_reason("BEService.exe") == Some(ProtectionReason::AntiCheat)
        && immutable_protection_reason("Ricochet.exe") == Some(ProtectionReason::AntiCheat);
    let svc_ok = is_critical_service("RpcSs")
        && is_critical_service("vgc")
        && !is_critical_service("WSearch")
        && win32_ops::start_service("RpcSs").is_err();
    let non_crit_ok = check_protection("chrome.exe", &[], Some("cs2.exe")).is_none();

    let tampered_reg = RegistryRecoveryRecord {
        hive: "HKLM".to_string(),
        subkey: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
        value_name: "Evil".to_string(),
        existed_before: true,
        previous_dword: Some(1),
    };
    let ipc_rejects_anticheat = matches!(
        handle_ipc_request(
            &pipe_backend,
            IpcRequest::AddProcessRule {
                exe_name: "vgc.exe".to_string(),
                action: ProcessAction::Suspend
            }
        ),
        IpcResponse::Error { .. }
    );
    let tamper_blocked = !is_allowed_recovery_registry_record(&tampered_reg)
        && !is_valid_qos_policy_name(r"WinBoost_..\Other")
        && ipc_rejects_anticheat;

    let mut snap = RecoveryState::new("cs2.exe", "Compétitif / Max FPS");
    snap.original_power_plan_guid = win32_ops::get_active_power_plan().map(|(g, _)| g);
    snap.suspended_processes.push(SuspendedProcessRecord {
        pid: 999999,
        exe_name: "chrome.exe".to_string(),
        creation_time: 123456789,
    });
    snap.stopped_services.push(ServiceRecoveryRecord {
        service_name: "WSearch".to_string(),
        was_running: true,
        was_paused: false,
    });

    let save_ok = snap.save_atomic(&temp_rec_path).is_ok();
    let crash_detected = RecoveryState::detect_unrestored(&temp_rec_path)
        .ok()
        .flatten()
        .map(|r| r.suspended_processes.len() == 1 && r.stopped_services.len() == 1)
        .unwrap_or(false);
    let cleanup_ok =
        snap.mark_restored_and_cleanup(&temp_rec_path).is_ok() && !temp_rec_path.exists();

    let ping_v4 = win32_ops::run_icmp_ping("Loopback v4", "127.0.0.1", 1);
    let ping_v6 = win32_ops::run_icmp_ping("Loopback v6", "::1", 1);
    let ping_ok = ping_v4.error.is_none() && ping_v6.error.is_none();

    let act_passed = core_ok
        && anticheat_ok
        && svc_ok
        && non_crit_ok
        && tamper_blocked
        && save_ok
        && crash_detected
        && cleanup_ok
        && ping_ok;

    steps.push(SelfTestStep {
        step: "act".to_string(),
        passed: act_passed,
        detail: format!(
            "Whitelist & validation IPC/registre OK, MoveFileExW={}, crash-recovery={}, Ping IPv4/IPv6={}",
            save_ok, crash_detected, ping_ok
        ),
    });

    // 3. `hud` : Direct2D + DirectWrite natif + télémétrie CPU/RAM/processus
    let d2d_ok = ui::verify_direct2d_available().is_ok();
    let mut monitor = SystemMonitor::new();
    std::thread::sleep(Duration::from_millis(80));
    monitor.sample();
    engine.refresh_processes_and_services();

    let ram_valid = monitor.current.ram_total_gb > 0.5 && monitor.current.ram_used_gb > 0.0;
    let procs_valid = engine.running_processes.len() > 10;
    let power_valid = !engine.capabilities.active_power_plan_name.is_empty();
    let hud_passed = d2d_ok && ram_valid && procs_valid && power_valid;

    steps.push(SelfTestStep {
        step: "hud".to_string(),
        passed: hud_passed,
        detail: format!(
            "Direct2D/DirectWrite={}, CPU {:.1} %, RAM {:.1}/{:.1} Go, {} processus, plan « {} », RAM proc {:.1} Mo",
            d2d_ok,
            monitor.current.cpu_usage_percent,
            monitor.current.ram_used_gb,
            monitor.current.ram_total_gb,
            engine.running_processes.len(),
            engine.capabilities.active_power_plan_name,
            monitor.current.app_ram_mb
        ),
    });

    let all_passed = steps.iter().all(|s| s.passed);
    let report = SelfTestReport { version: 1, steps };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(output_path, json).map_err(|e| e.to_string())?;

    Ok(all_passed)
}
