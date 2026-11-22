#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `winboost-ui.exe` — Interface bureau native Win32 + Direct2D + DirectWrite (< 20 Mo RAM).
//!
//! Architecture découplée :
//! - S'ouvre uniquement à la demande (clic Tray ou lancement direct).
//! - Communique avec `winboost-svc.exe` via Named Pipe sécurisé (`\\.\pipe\WinBoost`).
//! - Se ferme complètement à la croix (0 Mo RAM en jeu) pendant que le daemon reste dans le Tray.
//! - Conserve `--screenshot <file.png>` et `--self-test <file.json>`.

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use winboost::ipc::IpcClient;
use winboost::self_test;
use winboost::ui;
use winboost::win32_ops::{self, SingleInstanceGuard};

const DETACHED_PROCESS: u32 = 0x0000_0008;

struct CliOptions {
    screenshot: Option<PathBuf>,
    self_test_out: Option<PathBuf>,
    elevated_handoff_pid: Option<u32>,
}

fn parse_cli_args() -> CliOptions {
    let mut args = std::env::args().skip(1);
    let mut opts = CliOptions {
        screenshot: None,
        self_test_out: None,
        elevated_handoff_pid: None,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--screenshot" => {
                if let Some(p) = args.next() {
                    opts.screenshot = Some(PathBuf::from(p));
                }
            }
            "--self-test" => {
                if let Some(p) = args.next() {
                    opts.self_test_out = Some(PathBuf::from(p));
                }
            }
            "--elevated-handoff" => {
                if let Some(pid_str) = args.next() {
                    opts.elevated_handoff_pid = pid_str.parse::<u32>().ok();
                }
            }
            _ => {}
        }
    }
    opts
}

fn acquire_ui_single_instance(handoff_pid: Option<u32>) -> Option<SingleInstanceGuard> {
    let deadline =
        Instant::now() + Duration::from_millis(if handoff_pid.is_some() { 2500 } else { 0 });
    loop {
        match SingleInstanceGuard::try_acquire() {
            Ok(Some(guard)) => return Some(guard),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(_) => return None,
        }
    }
}

/// Démarre automatiquement `winboost-svc.exe` si le daemon n'est pas encore joignable.
fn ensure_service_running() -> bool {
    let client = IpcClient::default_pipe();
    if client.is_service_alive() {
        return true;
    }

    if let Ok(cur_exe) = std::env::current_exe() {
        if let Some(dir) = cur_exe.parent() {
            let svc_exe = dir.join("winboost-svc.exe");
            if svc_exe.is_file() {
                let _ = Command::new(svc_exe).creation_flags(DETACHED_PROCESS).spawn();
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(80));
                    if client.is_service_alive() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn main() {
    let opts = parse_cli_args();

    // 1. Mode auto-test (`--self-test <file.json>`)
    if let Some(report_path) = opts.self_test_out {
        match self_test::run_self_test(&report_path) {
            Ok(true) => std::process::exit(0),
            Ok(false) => {
                eprintln!("Certaines vérifications --self-test ont échoué.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Erreur --self-test: {}", e);
                std::process::exit(1);
            }
        }
    }

    // 2. Garde mono-instance UI (hors capture automatisée)
    let instance_guard = if opts.screenshot.is_none() {
        match acquire_ui_single_instance(opts.elevated_handoff_pid) {
            Some(guard) => Some(guard),
            None => {
                win32_ops::focus_existing_instance();
                std::process::exit(0);
            }
        }
    } else {
        None
    };

    // 3. Connexion au daemon `winboost-svc.exe` (lancement auto hors mode --screenshot)
    let use_ipc = if opts.screenshot.is_none() {
        ensure_service_running()
    } else {
        false
    };

    // 4. Lancement de la fenêtre native Win32 + Direct2D + DirectWrite
    if let Err(e) = ui::run_native_ui(instance_guard, use_ipc, opts.screenshot) {
        eprintln!("Erreur interface Direct2D : {}", e);
        std::process::exit(1);
    }
}
