#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `winboost-svc.exe` — Daemon / Service d'arrière-plan ultra-léger (< 5 Mo RAM, 0 Mo VRAM).
//!
//! Responsabilités :
//! - Héberge `BoostEngine`, Auto-Boost (scan léger 2,5 s) et Crash-Recovery au démarrage.
//! - Héberge `SystemMonitor` (en pause totale dès qu'aucun client UI n'est connecté).
//! - Expose le serveur Named Pipe sécurisé `\\.\pipe\WinBoost` avec ACL stricte.
//! - Gère l'icône System Tray et lance `winboost-ui.exe` uniquement à la demande.

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
};

use winboost::ipc::{run_pipe_server_loop, ServiceBackend, DEFAULT_PIPE_NAME};
use winboost::models::AppConfig;
use winboost::recovery::RecoveryState;
use winboost::self_test;
use winboost::tray::{TrayAction, TrayController};
use winboost::win32_ops::{self, to_wide_null};

const SVC_MUTEX_NAME: &str = r"Local\WinBoost_Service_Mutex";
const DETACHED_PROCESS: u32 = 0x0000_0008;

struct SvcMutexGuard(HANDLE);

impl SvcMutexGuard {
    fn acquire(wait_ms: u64) -> Option<Self> {
        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        let name_w = to_wide_null(SVC_MUTEX_NAME);
        loop {
            let h = unsafe { CreateMutexW(null(), 1, name_w.as_ptr()) };
            if !h.is_null() {
                if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                    return Some(Self(h));
                }
                unsafe {
                    CloseHandle(h);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(80));
        }
    }
}

impl Drop for SvcMutexGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }
}

fn find_sibling_ui_exe() -> Option<PathBuf> {
    let cur = std::env::current_exe().ok()?;
    let dir = cur.parent()?;
    let candidate = dir.join("winboost-ui.exe");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn launch_or_focus_ui() {
    // Si une fenêtre UI est déjà ouverte, la ramène simplement au premier plan
    win32_ops::focus_existing_instance();
    if let Some(ui_exe) = find_sibling_ui_exe() {
        let _ = Command::new(ui_exe).creation_flags(DETACHED_PROCESS).spawn();
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut handoff = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--self-test" => {
                if let Some(p) = args.next() {
                    match self_test::run_self_test(std::path::Path::new(&p)) {
                        Ok(true) => std::process::exit(0),
                        _ => std::process::exit(1),
                    }
                }
            }
            "--screenshot" => {
                if let Some(p) = args.next() {
                    if let Some(ui_exe) = find_sibling_ui_exe() {
                        let status = Command::new(ui_exe).args(["--screenshot", &p]).status();
                        std::process::exit(status.map(|s| s.code().unwrap_or(1)).unwrap_or(1));
                    }
                    std::process::exit(1);
                }
            }
            "--elevated-handoff" => {
                handoff = true;
                let _ = args.next();
            }
            _ => {}
        }
    }

    // Une seule instance du daemon par session
    let Some(_svc_guard) = SvcMutexGuard::acquire(if handoff { 2500 } else { 0 }) else {
        std::process::exit(0);
    };

    let config = AppConfig::load_or_default();
    let recovery_path = RecoveryState::default_path();
    let backend = Arc::new(Mutex::new(ServiceBackend::new(config, recovery_path)));

    // 1. Thread serveur Named Pipe sécurisé (`\\.\pipe\WinBoost`)
    {
        let pipe_backend = Arc::clone(&backend);
        std::thread::spawn(move || {
            run_pipe_server_loop(DEFAULT_PIPE_NAME.to_string(), pipe_backend);
        });
    }

    // 2. Thread léger Auto-Boost (2.5s) + Monitoring conditionnel (uniquement si UI connectée)
    {
        let loop_backend = Arc::clone(&backend);
        std::thread::spawn(move || {
            let mut last_auto_poll = Instant::now();
            let mut last_trim = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let mut b = loop_backend.lock().unwrap();
                if b.shutdown_requested {
                    break;
                }

                // Monitoring uniquement si l'UI a récemment demandé l'état
                b.tick_monitoring_if_ui_connected();

                let poll_ms = b.engine.config.poll_interval_ms.clamp(1500, 10_000);
                if last_auto_poll.elapsed() >= Duration::from_millis(poll_ms) {
                    if let Some(toast) = b.engine.poll_auto_boost() {
                        b.last_banner = Some((toast, false));
                    }
                    last_auto_poll = Instant::now();
                }

                // Maintien de l'empreinte RAM < 5 Mo en veille lorsqu'aucune UI n'est ouverte
                if !b.has_active_ui_client() && last_trim.elapsed() >= Duration::from_secs(30) {
                    win32_ops::trim_self_working_set();
                    last_trim = Instant::now();
                }
            }
        });
    }

    // 3. Icône System Tray + pompe de messages Win32 légère sur le thread principal
    let tray = TrayController::create().ok();
    win32_ops::trim_self_working_set();

    let mut last_tray_sync = Instant::now();
    let mut msg: MSG = unsafe { std::mem::zeroed() };

    loop {
        unsafe {
            while PeekMessageW(&mut msg, null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        if let Some(ref tray_ctrl) = tray {
            for action in tray_ctrl.poll_actions() {
                match action {
                    TrayAction::ToggleBoost => {
                        let mut b = backend.lock().unwrap();
                        if b.engine.stats.active {
                            b.engine.deactivate_boost();
                        } else {
                            b.engine.activate_manual_boost();
                        }
                    }
                    TrayAction::SelectProfile(prof) => {
                        backend.lock().unwrap().engine.set_global_profile(prof);
                    }
                    TrayAction::ShowDashboard => {
                        launch_or_focus_ui();
                    }
                    TrayAction::QuitAndRestore => {
                        let mut b = backend.lock().unwrap();
                        if b.engine.stats.active {
                            b.engine.deactivate_boost();
                        }
                        b.shutdown_requested = true;
                    }
                }
            }

            if last_tray_sync.elapsed() >= Duration::from_millis(1200) {
                let b = backend.lock().unwrap();
                let prof_name = if b.engine.stats.active {
                    b.engine.stats.active_profile_name.clone()
                } else {
                    b.engine.config.active_global_profile.display_name()
                };
                tray_ctrl.update_status(
                    b.engine.stats.active,
                    &prof_name,
                    b.engine.stats.detected_game_name.as_deref(),
                );
                last_tray_sync = Instant::now();
            }
        }

        if backend.lock().unwrap().shutdown_requested {
            break;
        }

        std::thread::sleep(Duration::from_millis(80));
    }

    // Restauration finale garantie avant sortie
    {
        let mut b = backend.lock().unwrap();
        if b.engine.stats.active {
            b.engine.deactivate_boost();
        }
    }
}
