//! Opérations système bas niveau Windows 10/11 (Win32 / NTDLL / PowrProf / SCM / Registry / ICMP).
//!
//! Toutes les fonctions exposent des interfaces Rust sûres, appliquent une validation stricte
//! (anti-tampering, whitelist inviolable, protection anti-DLL hijacking `LOAD_LIBRARY_SEARCH_SYSTEM32`),
//! et gèrent proprement les erreurs d'accès hors mode Administrateur.

use std::ffi::{c_void, OsStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::ptr::{null, null_mut};

use chrono::Local;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, GetLastError, LocalFree, BOOL, ERROR_ALREADY_EXISTS, FALSE, FILETIME,
    HANDLE, HMODULE, HWND, INVALID_HANDLE_VALUE, LPARAM, LUID,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    Icmp6CreateFile, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMPV6_ECHO_REPLY_LH,
    ICMP_ECHO_REPLY,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EmptyWorkingSet, K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE,
    KEY_WRITE, REG_DWORD, REG_SZ,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    StartServiceW, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_STOP,
    SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetCurrentProcessId, GetPriorityClass,
    GetProcessAffinityMask, GetProcessTimes, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, ReleaseMutex, SetPriorityClass, SetProcessAffinityMask,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA,
    PROCESS_SUSPEND_RESUME,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, FindWindowW, GetWindowThreadProcessId, PostMessageW, SetForegroundWindow,
    ShowWindow, SW_RESTORE, SW_SHOWNORMAL, WM_CLOSE,
};

use crate::models::{PingResult, PowerPlanTarget, SafeCpuPriority};
use crate::recovery::{
    is_allowed_recovery_registry_record, is_valid_power_guid, is_valid_qos_policy_name,
    is_valid_service_name, RegistryRecoveryRecord,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// GUIDs officiels des plans d'alimentation Windows 10/11.
pub const GUID_POWER_BALANCED: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";
pub const GUID_POWER_HIGH_PERF: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
pub const GUID_POWER_ULTIMATE: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";

/// Nom du mutex Windows garantissant une instance unique par session utilisateur.
pub const SINGLE_INSTANCE_MUTEX_NAME: &str = r"Local\WinBoost_SingleInstance_Mutex";
/// Titre exact de la fenêtre principale pour la ramener au premier plan si déjà lancée.
pub const MAIN_WINDOW_TITLE: &str = "WinBoost — Optimiseur & nettoyeur Windows";

/// Encodage UTF-16 terminé par NUL pour les APIs Win32 `*W`.
pub fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Garde RAII pour le mutex mono-instance (`CreateMutexW`).
pub struct SingleInstanceGuard {
    handle: HANDLE,
}

impl SingleInstanceGuard {
    /// Tente d'acquérir le mutex mono-instance. Retourne `Ok(Some(guard))` si acquis,
    /// `Ok(None)` si une autre instance est déjà active.
    pub fn try_acquire() -> Result<Option<Self>, String> {
        let name_w = to_wide_null(SINGLE_INSTANCE_MUTEX_NAME);
        unsafe {
            let handle = CreateMutexW(null(), 1, name_w.as_ptr());
            if handle.is_null() {
                return Err(format!("CreateMutexW échec (code {})", GetLastError()));
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(handle);
                return Ok(None);
            }
            Ok(Some(Self { handle }))
        }
    }

    /// Libère explicitement le mutex avant de fermer l'ancienne instance lors d'un relancement Admin.
    pub fn release_now(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
            self.handle = null_mut();
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        self.release_now();
    }
}

/// Ramène la fenêtre d'une instance WinBoost déjà ouverte au premier plan.
pub fn focus_existing_instance() {
    let title_w = to_wide_null(MAIN_WINDOW_TITLE);
    unsafe {
        let hwnd = FindWindowW(null(), title_w.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

/// Informations brutes d'un processus Windows énuméré par snapshot Toolhelp32.
#[derive(Debug, Clone)]
pub struct RawProcessEntry {
    pub pid: u32,
    pub exe_name: String,
    pub full_path: Option<String>,
    pub working_set_bytes: u64,
    pub creation_time: u64,
}

/// Vérifie si le processus courant possède des privilèges Administrateur (TokenElevation).
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Relance l'application avec élévation UAC (`ShellExecuteW` verbe `"runas"`),
/// en transmettant `--elevated-handoff <pid>` pour une passation mono-instance propre.
pub fn relaunch_as_admin() -> Result<(), String> {
    let exe_path = std::env::current_exe().map_err(|e| format!("Chemin exe introuvable: {}", e))?;
    let exe_w = to_wide_null(&exe_path.to_string_lossy());
    let verb_w = to_wide_null("runas");
    let pid = unsafe { GetCurrentProcessId() };
    let params_w = to_wide_null(&format!("--elevated-handoff {}", pid));

    unsafe {
        let result = ShellExecuteW(
            null_mut(),
            verb_w.as_ptr(),
            exe_w.as_ptr(),
            params_w.as_ptr(),
            null(),
            SW_SHOWNORMAL,
        );
        if (result as isize) > 32 {
            Ok(())
        } else {
            Err(format!(
                "Élévation UAC annulée ou refusée (code {})",
                result as isize
            ))
        }
    }
}

/// Énumération ultra-légère des processus actifs (< 1 ms, zéro allocation WMI).
pub fn enumerate_processes(include_paths_and_mem: bool) -> Vec<RawProcessEntry> {
    let mut results = Vec::with_capacity(200);
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return results;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..end]);

                let mut full_path = None;
                let mut working_set_bytes = 0u64;
                let mut creation_time = 0u64;

                if include_paths_and_mem && pid > 4 {
                    let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                    if !handle.is_null() {
                        let mut buf = [0u16; 512];
                        let mut len = buf.len() as u32;
                        if QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) != 0 {
                            full_path = Some(String::from_utf16_lossy(&buf[..len as usize]));
                        }

                        let mut ct: FILETIME = std::mem::zeroed();
                        let mut et: FILETIME = std::mem::zeroed();
                        let mut kt: FILETIME = std::mem::zeroed();
                        let mut ut: FILETIME = std::mem::zeroed();
                        if GetProcessTimes(handle, &mut ct, &mut et, &mut kt, &mut ut) != 0 {
                            creation_time = filetime_to_u64(ct);
                        }

                        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                        if K32GetProcessMemoryInfo(handle, &mut pmc, pmc.cb) != 0 {
                            working_set_bytes = pmc.WorkingSetSize as u64;
                        }

                        CloseHandle(handle);
                    }
                }

                results.push(RawProcessEntry {
                    pid,
                    exe_name,
                    full_path,
                    working_set_bytes,
                    creation_time,
                });

                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snap);
    }
    results
}

/// Récupère le temps de création (FILETIME) d'un PID pour prévenir les collisions de PID recyclé.
pub fn get_process_creation_time(pid: u32) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if handle.is_null() {
            return None;
        }
        let mut ct: FILETIME = std::mem::zeroed();
        let mut et: FILETIME = std::mem::zeroed();
        let mut kt: FILETIME = std::mem::zeroed();
        let mut ut: FILETIME = std::mem::zeroed();
        let ok = GetProcessTimes(handle, &mut ct, &mut et, &mut kt, &mut ut) != 0;
        CloseHandle(handle);
        if ok {
            Some(filetime_to_u64(ct))
        } else {
            None
        }
    }
}

/// Suspend un processus de manière réversible via `ntdll.dll!NtSuspendProcess`.
pub fn suspend_process(pid: u32) -> Result<u64, String> {
    unsafe {
        if pid == GetCurrentProcessId() || pid <= 4 {
            return Err("Processus système ou courant interdit".to_string());
        }

        type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;
        let ntdll = GetModuleHandleW(to_wide_null("ntdll.dll").as_ptr());
        if ntdll.is_null() {
            return Err("ntdll.dll introuvable".to_string());
        }
        let proc_addr = GetProcAddress(ntdll, b"NtSuspendProcess\0".as_ptr());
        let Some(func_ptr) = proc_addr else {
            return Err("NtSuspendProcess indisponible".to_string());
        };
        let nt_suspend: NtSuspendProcessFn = std::mem::transmute(func_ptr);

        let handle = OpenProcess(
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid,
        );
        if handle.is_null() {
            return Err(format!("Accès refusé pour PID {}", pid));
        }

        let mut ct: FILETIME = std::mem::zeroed();
        let mut et: FILETIME = std::mem::zeroed();
        let mut kt: FILETIME = std::mem::zeroed();
        let mut ut: FILETIME = std::mem::zeroed();
        let creation_time = if GetProcessTimes(handle, &mut ct, &mut et, &mut kt, &mut ut) != 0 {
            filetime_to_u64(ct)
        } else {
            0
        };

        let status = nt_suspend(handle);
        CloseHandle(handle);
        if status == 0 {
            Ok(creation_time)
        } else {
            Err(format!("NtSuspendProcess échec (NTSTATUS 0x{:08X})", status))
        }
    }
}

/// Reprend un processus suspendu via `ntdll.dll!NtResumeProcess`, après vérification du `creation_time`.
pub fn resume_process(pid: u32, expected_creation_time: u64) -> Result<bool, String> {
    unsafe {
        type NtResumeProcessFn = unsafe extern "system" fn(HANDLE) -> i32;
        let ntdll = GetModuleHandleW(to_wide_null("ntdll.dll").as_ptr());
        if ntdll.is_null() {
            return Err("ntdll.dll introuvable".to_string());
        }
        let proc_addr = GetProcAddress(ntdll, b"NtResumeProcess\0".as_ptr());
        let Some(func_ptr) = proc_addr else {
            return Err("NtResumeProcess indisponible".to_string());
        };
        let nt_resume: NtResumeProcessFn = std::mem::transmute(func_ptr);

        let handle = OpenProcess(
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid,
        );
        if handle.is_null() {
            return Ok(false);
        }

        if expected_creation_time != 0 {
            let mut ct: FILETIME = std::mem::zeroed();
            let mut et: FILETIME = std::mem::zeroed();
            let mut kt: FILETIME = std::mem::zeroed();
            let mut ut: FILETIME = std::mem::zeroed();
            if GetProcessTimes(handle, &mut ct, &mut et, &mut kt, &mut ut) != 0 {
                let actual = filetime_to_u64(ct);
                if actual != expected_creation_time {
                    CloseHandle(handle);
                    return Ok(false);
                }
            }
        }

        let status = nt_resume(handle);
        CloseHandle(handle);
        if status == 0 {
            Ok(true)
        } else {
            Err(format!("NtResumeProcess échec (NTSTATUS 0x{:08X})", status))
        }
    }
}

/// Envoie `WM_CLOSE` aux fenêtres principales d'un processus pour une fermeture propre.
pub fn close_process_gracefully(pid: u32) -> bool {
    struct CloseContext {
        target_pid: u32,
        sent_count: usize,
    }

    unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam as *mut CloseContext);
        let mut win_pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut win_pid);
        if win_pid == ctx.target_pid {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            ctx.sent_count += 1;
        }
        1
    }

    let mut ctx = CloseContext {
        target_pid: pid,
        sent_count: 0,
    };
    unsafe {
        EnumWindows(Some(enum_cb), &mut ctx as *mut _ as LPARAM);
    }
    ctx.sent_count > 0
}

/// Calcule un masque d'affinité CPU sûr qui exclut le Core 0 si le CPU a au moins 4 cœurs logiques.
pub fn compute_safe_affinity_mask(system_mask: usize, avoid_core_0: bool) -> Option<usize> {
    if !avoid_core_0 {
        return None;
    }
    let logical_cores = system_mask.count_ones();
    if logical_cores < 4 {
        return None;
    }
    let new_mask = system_mask & !1usize;
    if new_mask != 0 && new_mask != system_mask {
        Some(new_mask)
    } else {
        None
    }
}

/// Applique une priorité CPU sûre (jamais Realtime) et optionnellement un masque d'affinité.
pub fn apply_game_cpu_optimization(
    pid: u32,
    priority: SafeCpuPriority,
    avoid_core_0: bool,
) -> Result<(u64, u32, Option<usize>), String> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid,
        );
        if handle.is_null() {
            return Err(format!(
                "Impossible d'ouvrir le jeu PID {} (privilèges requis ?)",
                pid
            ));
        }

        let mut ct: FILETIME = std::mem::zeroed();
        let mut et: FILETIME = std::mem::zeroed();
        let mut kt: FILETIME = std::mem::zeroed();
        let mut ut: FILETIME = std::mem::zeroed();
        let creation_time = if GetProcessTimes(handle, &mut ct, &mut et, &mut kt, &mut ut) != 0 {
            filetime_to_u64(ct)
        } else {
            0
        };

        let old_priority = GetPriorityClass(handle);
        let new_class = priority.to_win32_class();
        if SetPriorityClass(handle, new_class) == 0 {
            CloseHandle(handle);
            return Err(format!("SetPriorityClass refusé pour PID {}", pid));
        }

        let mut old_affinity_saved = None;
        if avoid_core_0 {
            let mut proc_mask: usize = 0;
            let mut sys_mask: usize = 0;
            if GetProcessAffinityMask(handle, &mut proc_mask, &mut sys_mask) != 0 {
                if let Some(target_mask) = compute_safe_affinity_mask(sys_mask, true) {
                    if SetProcessAffinityMask(handle, target_mask) != 0 {
                        old_affinity_saved = Some(proc_mask);
                    }
                }
            }
        }

        CloseHandle(handle);
        Ok((creation_time, old_priority, old_affinity_saved))
    }
}

/// Restaure la priorité CPU et l'affinité d'un processus (après contrôle du `creation_time`).
pub fn restore_process_cpu_optimization(
    pid: u32,
    expected_creation_time: u64,
    original_priority_class: u32,
    original_affinity_mask: Option<usize>,
) -> bool {
    unsafe {
        let handle = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid,
        );
        if handle.is_null() {
            return false;
        }
        if expected_creation_time != 0 {
            let mut ct: FILETIME = std::mem::zeroed();
            let mut et: FILETIME = std::mem::zeroed();
            let mut kt: FILETIME = std::mem::zeroed();
            let mut ut: FILETIME = std::mem::zeroed();
            if GetProcessTimes(handle, &mut ct, &mut et, &mut kt, &mut ut) != 0 {
                if filetime_to_u64(ct) != expected_creation_time {
                    CloseHandle(handle);
                    return false;
                }
            }
        }
        if original_priority_class != 0 {
            let _ = SetPriorityClass(handle, original_priority_class);
        }
        if let Some(mask) = original_affinity_mask {
            if mask != 0 {
                let _ = SetProcessAffinityMask(handle, mask);
            }
        }
        CloseHandle(handle);
        true
    }
}

/// Réduit le Working Set de WinBoost lui-même lors de la mise en veille dans le System Tray
/// afin de maintenir une empreinte mémoire minimale (< 50 Mo) en arrière-plan.
pub fn trim_self_working_set() {
    unsafe {
        let _ = K32EmptyWorkingSet(GetCurrentProcess());
    }
}

/// Libère en sécurité le Working Set d'un processus non critique et retourne les octets libérés estimés.
pub fn trim_process_working_set(pid: u32) -> u64 {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA,
            FALSE,
            pid,
        );
        if handle.is_null() {
            return 0;
        }
        let mut before: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        before.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let has_before = K32GetProcessMemoryInfo(handle, &mut before, before.cb) != 0;

        let ok = K32EmptyWorkingSet(handle) != 0;

        let mut freed = 0u64;
        if ok && has_before {
            let mut after: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            after.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if K32GetProcessMemoryInfo(handle, &mut after, after.cb) != 0 {
                freed = (before.WorkingSetSize as u64).saturating_sub(after.WorkingSetSize as u64);
            }
        }
        CloseHandle(handle);
        freed
    }
}

fn enable_token_privilege(privilege_name: &str) -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }
        let mut luid: LUID = std::mem::zeroed();
        let name_w = to_wide_null(privilege_name);
        if LookupPrivilegeValueW(null(), name_w.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, null_mut(), null_mut()) != 0;
        CloseHandle(token);
        ok
    }
}

/// Purge la Standby List Windows via `NtSetSystemInformation(SystemMemoryListInformation)` (Admin requis).
pub fn purge_standby_list() -> Result<(), String> {
    if !is_elevated() {
        return Err("Privilèges Administrateur requis pour purger la Standby List".to_string());
    }
    let _ = enable_token_privilege("SeProfileSingleProcessPrivilege");
    unsafe {
        type NtSetSystemInformationFn =
            unsafe extern "system" fn(i32, *mut c_void, u32) -> i32;
        let ntdll = GetModuleHandleW(to_wide_null("ntdll.dll").as_ptr());
        if ntdll.is_null() {
            return Err("ntdll.dll introuvable".to_string());
        }
        let Some(fn_ptr) = GetProcAddress(ntdll, b"NtSetSystemInformation\0".as_ptr()) else {
            return Err("NtSetSystemInformation indisponible".to_string());
        };
        let nt_set_sys_info: NtSetSystemInformationFn = std::mem::transmute(fn_ptr);

        const SYSTEM_MEMORY_LIST_INFORMATION: i32 = 80;
        let mut memory_purge_standby_list: u32 = 4;
        let status = nt_set_sys_info(
            SYSTEM_MEMORY_LIST_INFORMATION,
            &mut memory_purge_standby_list as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
        );
        if status == 0 {
            Ok(())
        } else {
            Err(format!("Purge Standby List refusée (NTSTATUS 0x{:08X})", status))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PLANS D'ALIMENTATION : API NATIVE `powrprof.dll` (SANS SPAWN DE PROCESSUS)
// ═══════════════════════════════════════════════════════════════════════════

struct SystemDll(HMODULE);
impl SystemDll {
    fn load_system32(name: &str) -> Option<Self> {
        let w = to_wide_null(name);
        let h = unsafe { LoadLibraryExW(w.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if h.is_null() {
            None
        } else {
            Some(Self(h))
        }
    }
}
impl Drop for SystemDll {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }
}

/// Convertit un `GUID` Win32 en chaîne canonique minuscule `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn format_guid(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

/// Parse une chaîne GUID canonique en structure Win32 `GUID`.
pub fn parse_guid_struct(s: &str) -> Option<GUID> {
    if !is_valid_power_guid(s) {
        return None;
    }
    let data1 = u32::from_str_radix(&s[0..8], 16).ok()?;
    let data2 = u16::from_str_radix(&s[9..13], 16).ok()?;
    let data3 = u16::from_str_radix(&s[14..18], 16).ok()?;
    let mut data4 = [0u8; 8];
    data4[0] = u8::from_str_radix(&s[19..21], 16).ok()?;
    data4[1] = u8::from_str_radix(&s[21..23], 16).ok()?;
    for i in 0..6 {
        let offset = 24 + i * 2;
        data4[2 + i] = u8::from_str_radix(&s[offset..offset + 2], 16).ok()?;
    }
    Some(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn friendly_name_for_known_guid(guid: &str) -> Option<&'static str> {
    match guid {
        GUID_POWER_BALANCED => Some("Usage normal (Équilibré)"),
        GUID_POWER_HIGH_PERF => Some("Performances élevées"),
        GUID_POWER_ULTIMATE => Some("Performances optimales (Ultimate)"),
        _ => None,
    }
}

/// Lit le GUID et le nom convivial du plan d'alimentation actif via `powrprof.dll`
/// (`PowerGetActiveScheme` + `PowerReadFriendlyName`), avec repli `powercfg` si nécessaire.
pub fn get_active_power_plan() -> Option<(String, String)> {
    if let Some(res) = get_active_power_plan_native() {
        return Some(res);
    }
    let out = Command::new("powercfg")
        .args(["/getactivescheme"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_powercfg_guid_and_name(&text)
}

fn get_active_power_plan_native() -> Option<(String, String)> {
    type PowerGetActiveSchemeFn = unsafe extern "system" fn(HKEY, *mut *mut GUID) -> u32;
    type PowerReadFriendlyNameFn = unsafe extern "system" fn(
        HKEY,
        *const GUID,
        *const GUID,
        *const GUID,
        *mut u8,
        *mut u32,
    ) -> u32;

    let dll = SystemDll::load_system32("powrprof.dll")?;
    unsafe {
        let get_active: PowerGetActiveSchemeFn =
            std::mem::transmute(GetProcAddress(dll.0, b"PowerGetActiveScheme\0".as_ptr())?);
        let read_name: Option<PowerReadFriendlyNameFn> =
            GetProcAddress(dll.0, b"PowerReadFriendlyName\0".as_ptr())
                .map(|p| std::mem::transmute(p));

        let mut scheme_ptr: *mut GUID = null_mut();
        if get_active(null_mut(), &mut scheme_ptr) != 0 || scheme_ptr.is_null() {
            return None;
        }
        let scheme = *scheme_ptr;
        LocalFree(scheme_ptr as *mut c_void);

        let guid_str = format_guid(&scheme);
        let mut friendly = None;

        if let Some(read_fn) = read_name {
            let mut size: u32 = 0;
            if read_fn(null_mut(), &scheme, null(), null(), null_mut(), &mut size) == 0 && size >= 2
            {
                let mut buf = vec![0u8; size as usize];
                if read_fn(
                    null_mut(),
                    &scheme,
                    null(),
                    null(),
                    buf.as_mut_ptr(),
                    &mut size,
                ) == 0
                {
                    let u16s: Vec<u16> = buf
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&w| w != 0)
                        .collect();
                    let name = String::from_utf16_lossy(&u16s).trim().to_string();
                    if !name.is_empty() {
                        friendly = Some(name);
                    }
                }
            }
        }

        let label = friendly
            .or_else(|| friendly_name_for_known_guid(&guid_str).map(String::from))
            .unwrap_or_else(|| guid_str.clone());
        Some((guid_str, label))
    }
}

/// Parse la sortie de `powercfg /getactivescheme` indépendamment de la langue Windows (FR/EN/etc.).
pub fn parse_powercfg_guid_and_name(output: &str) -> Option<(String, String)> {
    let mut found_guid = None;
    for token in output.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != '-');
        if is_valid_power_guid(cleaned) {
            found_guid = Some(cleaned.to_ascii_lowercase());
            break;
        }
    }
    let guid = found_guid?;
    let name = output
        .rfind('(')
        .and_then(|start| {
            output[start + 1..]
                .find(')')
                .map(|end| output[start + 1..start + 1 + end].trim().to_string())
        })
        .unwrap_or_else(|| guid.clone());
    Some((guid, name))
}

/// Active un plan d'alimentation Windows par GUID via `powrprof.dll!PowerSetActiveScheme`
/// (avec validation stricte du GUID et repli `powercfg` si nécessaire).
pub fn set_power_plan_guid(guid: &str) -> Result<(), String> {
    let scheme = parse_guid_struct(guid)
        .ok_or_else(|| format!("GUID de plan d'alimentation invalide : {}", guid))?;

    if let Some(dll) = SystemDll::load_system32("powrprof.dll") {
        type PowerSetActiveSchemeFn = unsafe extern "system" fn(HKEY, *const GUID) -> u32;
        unsafe {
            if let Some(fn_ptr) = GetProcAddress(dll.0, b"PowerSetActiveScheme\0".as_ptr()) {
                let set_active: PowerSetActiveSchemeFn = std::mem::transmute(fn_ptr);
                let rc = set_active(null_mut(), &scheme);
                if rc == 0 {
                    return Ok(());
                }
            }
        }
    }

    // Repli powercfg si powrprof.dll indisponible ou refusé
    let out = Command::new("powercfg")
        .args(["/setactive", guid])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Échec exécution powercfg: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Activation plan {} refusée: {}",
            guid,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Active le plan d'alimentation cible (avec repli automatique vers Performances élevées).
pub fn apply_power_plan_target(target: PowerPlanTarget) -> Result<(String, String), String> {
    match target {
        PowerPlanTarget::KeepCurrent => get_active_power_plan()
            .ok_or_else(|| "Impossible de lire le plan d'alimentation actif".to_string()),
        PowerPlanTarget::Balanced => {
            set_power_plan_guid(GUID_POWER_BALANCED)?;
            Ok((
                GUID_POWER_BALANCED.to_string(),
                "Usage normal (Équilibré)".to_string(),
            ))
        }
        PowerPlanTarget::HighPerformance => {
            if set_power_plan_guid(GUID_POWER_HIGH_PERF).is_ok() {
                return Ok((
                    GUID_POWER_HIGH_PERF.to_string(),
                    "Performances élevées".to_string(),
                ));
            }
            if let Ok(dup_guid) = duplicate_power_scheme(GUID_POWER_HIGH_PERF) {
                set_power_plan_guid(&dup_guid)?;
                return Ok((dup_guid, "Performances élevées".to_string()));
            }
            Err("Plan Performances élevées indisponible sur ce matériel (Modern Standby)".to_string())
        }
        PowerPlanTarget::UltimatePerformance => {
            if let Some(existing) = find_power_scheme_by_name_or_guid(GUID_POWER_ULTIMATE, "ultimate")
                .or_else(|| find_power_scheme_by_name_or_guid(GUID_POWER_ULTIMATE, "optimales"))
            {
                if set_power_plan_guid(&existing).is_ok() {
                    return Ok((existing, "Performances optimales (Ultimate)".to_string()));
                }
            }
            if let Ok(dup_guid) = duplicate_power_scheme(GUID_POWER_ULTIMATE) {
                if set_power_plan_guid(&dup_guid).is_ok() {
                    return Ok((dup_guid, "Performances optimales (Ultimate)".to_string()));
                }
            }
            apply_power_plan_target(PowerPlanTarget::HighPerformance)
        }
    }
}

fn duplicate_power_scheme(template_guid: &str) -> Result<String, String> {
    let out = Command::new("powercfg")
        .args(["-duplicatescheme", template_guid])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_powercfg_guid_and_name(&text)
        .map(|(g, _)| g)
        .ok_or_else(|| "GUID dupliqué non trouvé".to_string())
}

fn find_power_scheme_by_name_or_guid(guid_hint: &str, name_hint: &str) -> Option<String> {
    let out = Command::new("powercfg")
        .args(["/list"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains(guid_hint) || lower.contains(name_hint) {
            if let Some((guid, _)) = parse_powercfg_guid_and_name(line) {
                return Some(guid);
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVICES WINDOWS (SCM) AVEC VALIDATION STRICTE ANTI-TAMPERING
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WinServiceState {
    Running,
    Paused,
    Stopped,
    Other,
    NotFoundOrDenied,
}

pub fn query_service_state(service_name: &str) -> WinServiceState {
    if !is_valid_service_name(service_name) {
        return WinServiceState::NotFoundOrDenied;
    }
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return WinServiceState::NotFoundOrDenied;
        }
        let svc_w = to_wide_null(service_name);
        let svc = OpenServiceW(scm, svc_w.as_ptr(), SERVICE_QUERY_STATUS);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return WinServiceState::NotFoundOrDenied;
        }
        let mut ssp: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed = 0u32;
        let ok = QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        );
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);

        if ok == 0 {
            return WinServiceState::Other;
        }
        match ssp.dwCurrentState {
            SERVICE_RUNNING => WinServiceState::Running,
            SERVICE_PAUSED => WinServiceState::Paused,
            SERVICE_STOPPED => WinServiceState::Stopped,
            _ => WinServiceState::Other,
        }
    }
}

/// Arrête proprement un service Windows non essentiel s'il est actuellement démarré.
pub fn stop_service_if_running(service_name: &str) -> Result<bool, String> {
    if !is_valid_service_name(service_name) {
        return Err(format!("Nom de service invalide : {}", service_name));
    }
    if crate::whitelist::is_critical_service(service_name) {
        return Err(format!(
            "Service critique {} protégé par la whitelist",
            service_name
        ));
    }
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err("Accès SCM refusé (Administrateur requis)".to_string());
        }
        let svc_w = to_wide_null(service_name);
        let svc = OpenServiceW(scm, svc_w.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_STOP);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return Err(format!(
                "Impossible d'ouvrir le service {} (droits Admin requis ou inexistant)",
                service_name
            ));
        }

        let mut ssp: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed = 0u32;
        let qok = QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        );
        if qok == 0 || ssp.dwCurrentState != SERVICE_RUNNING {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return Ok(false);
        }

        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok != 0 {
            Ok(true)
        } else {
            Err(format!("Arrêt du service {} refusé", service_name))
        }
    }
}

/// Redémarre un service Windows précédemment arrêté par WinBoost.
/// Valide également `is_valid_service_name` et `!is_critical_service` contre un `recovery_state.json` altéré.
pub fn start_service(service_name: &str) -> Result<(), String> {
    if !is_valid_service_name(service_name) {
        return Err(format!(
            "Nom de service rejeté lors de la restauration : {}",
            service_name
        ));
    }
    if crate::whitelist::is_critical_service(service_name) {
        return Err(format!(
            "Service critique {} refusé dans start_service (validation sécurité)",
            service_name
        ));
    }
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err("Accès SCM refusé".to_string());
        }
        let svc_w = to_wide_null(service_name);
        let svc = OpenServiceW(scm, svc_w.as_ptr(), SERVICE_START | SERVICE_QUERY_STATUS);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return Err(format!("Ouverture du service {} impossible", service_name));
        }

        let mut ssp: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed = 0u32;
        if QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            &mut ssp as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        ) != 0
            && ssp.dwCurrentState == SERVICE_RUNNING
        {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return Ok(());
        }

        let ok = StartServiceW(svc, 0, null());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok != 0 {
            Ok(())
        } else {
            Err(format!("Redémarrage du service {} refusé", service_name))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// REGISTRE & QoS DSCP AVEC ALLOWLIST STRICTE
// ═══════════════════════════════════════════════════════════════════════════

pub fn reg_read_dword(hklm: bool, subkey: &str, value_name: &str) -> Option<u32> {
    unsafe {
        let root: HKEY = if hklm {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let mut hkey: HKEY = null_mut();
        let subkey_w = to_wide_null(subkey);
        if RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return None;
        }
        let val_w = to_wide_null(value_name);
        let mut data: u32 = 0;
        let mut data_len: u32 = std::mem::size_of::<u32>() as u32;
        let mut val_type: u32 = 0;
        let rc = RegQueryValueExW(
            hkey,
            val_w.as_ptr(),
            null(),
            &mut val_type,
            &mut data as *mut _ as *mut u8,
            &mut data_len,
        );
        RegCloseKey(hkey);
        if rc == 0 && val_type == REG_DWORD {
            Some(data)
        } else {
            None
        }
    }
}

pub fn reg_write_dword(hklm: bool, subkey: &str, value_name: &str, value: u32) -> Result<(), String> {
    unsafe {
        let root: HKEY = if hklm {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let mut hkey: HKEY = null_mut();
        let subkey_w = to_wide_null(subkey);
        let rc = RegCreateKeyExW(
            root,
            subkey_w.as_ptr(),
            0,
            null(),
            0,
            KEY_WRITE,
            null(),
            &mut hkey,
            null_mut(),
        );
        if rc != 0 {
            return Err(format!(
                "Ouverture clé registre {} refusée (code {})",
                subkey, rc
            ));
        }
        let val_w = to_wide_null(value_name);
        let rc2 = RegSetValueExW(
            hkey,
            val_w.as_ptr(),
            0,
            REG_DWORD,
            &value as *const _ as *const u8,
            std::mem::size_of::<u32>() as u32,
        );
        RegCloseKey(hkey);
        if rc2 == 0 {
            Ok(())
        } else {
            Err(format!(
                "Écriture registre {} refusée (code {})",
                value_name, rc2
            ))
        }
    }
}

/// Restaure un changement registre enregistré dans `recovery_state.json`,
/// uniquement s'il appartient à l'allowlist stricte de sécurité.
pub fn restore_registry_record(rec: &RegistryRecoveryRecord) -> Result<(), String> {
    if !is_allowed_recovery_registry_record(rec) {
        return Err(format!(
            "Restauration registre bloquée (hors allowlist sécurité) : {}\\{}\\{}",
            rec.hive, rec.subkey, rec.value_name
        ));
    }
    let hklm = rec.hive.eq_ignore_ascii_case("HKLM");
    if rec.existed_before {
        if let Some(prev) = rec.previous_dword {
            return reg_write_dword(hklm, &rec.subkey, &rec.value_name, prev);
        }
    } else {
        unsafe {
            let root: HKEY = if hklm {
                HKEY_LOCAL_MACHINE
            } else {
                HKEY_CURRENT_USER
            };
            let mut hkey: HKEY = null_mut();
            let subkey_w = to_wide_null(&rec.subkey);
            if RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) == 0 {
                let val_w = to_wide_null(&rec.value_name);
                let _ = RegDeleteValueW(hkey, val_w.as_ptr());
                RegCloseKey(hkey);
            }
        }
    }
    Ok(())
}

pub fn is_windows_game_mode_enabled() -> Option<bool> {
    reg_read_dword(false, r"Software\Microsoft\GameBar", "AutoGameModeEnabled").map(|v| v != 0)
}

pub fn enable_windows_game_mode_reversible() -> Result<Option<RegistryRecoveryRecord>, String> {
    let prev = reg_read_dword(false, r"Software\Microsoft\GameBar", "AutoGameModeEnabled");
    if prev == Some(1) {
        return Ok(None);
    }
    reg_write_dword(false, r"Software\Microsoft\GameBar", "AutoGameModeEnabled", 1)?;
    Ok(Some(RegistryRecoveryRecord {
        hive: "HKCU".to_string(),
        subkey: r"Software\Microsoft\GameBar".to_string(),
        value_name: "AutoGameModeEnabled".to_string(),
        existed_before: prev.is_some(),
        previous_dword: prev,
    }))
}

pub fn is_hags_enabled() -> Option<bool> {
    reg_read_dword(
        true,
        r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        "HwSchMode",
    )
    .map(|v| v == 2)
}

/// Crée une stratégie réseau QoS Windows (DSCP 46) pour le jeu, après validation stricte du nom `WinBoost_*`.
pub fn apply_qos_dscp_policy(policy_name: &str, game_exe_name: &str) -> Result<(), String> {
    if !is_valid_qos_policy_name(policy_name) {
        return Err(format!(
            "Nom de stratégie QoS invalide (doit commencer par WinBoost_) : {}",
            policy_name
        ));
    }
    if !is_elevated() {
        return Err("Droits Administrateur requis pour la stratégie QoS DSCP".to_string());
    }
    let subkey = format!(r"SOFTWARE\Policies\Microsoft\Windows\QoS\{}", policy_name);
    let pairs = [
        ("Version", "1.0"),
        ("Application Name", game_exe_name),
        ("Protocol", "*"),
        ("Local Port", "*"),
        ("Local IP", "*"),
        ("Local IP Prefix Length", "*"),
        ("Remote Port", "*"),
        ("Remote IP", "*"),
        ("Remote IP Prefix Length", "*"),
        ("DSCP Value", "46"),
        ("Throttle Rate", "-1"),
    ];
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey_w = to_wide_null(&subkey);
        let rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            0,
            null(),
            0,
            KEY_WRITE,
            null(),
            &mut hkey,
            null_mut(),
        );
        if rc != 0 {
            return Err(format!("Création stratégie QoS refusée (code {})", rc));
        }
        for (k, v) in pairs {
            let kw = to_wide_null(k);
            let vw = to_wide_null(v);
            let _ = RegSetValueExW(
                hkey,
                kw.as_ptr(),
                0,
                REG_SZ,
                vw.as_ptr() as *const u8,
                (vw.len() * 2) as u32,
            );
        }
        RegCloseKey(hkey);
    }
    Ok(())
}

/// Supprime proprement une stratégie réseau QoS créée par WinBoost (`WinBoost_*` uniquement).
pub fn remove_qos_dscp_policy(policy_name: &str) -> Result<(), String> {
    if !is_valid_qos_policy_name(policy_name) {
        return Err(format!(
            "Suppression QoS bloquée (nom hors allowlist WinBoost_*) : {}",
            policy_name
        ));
    }
    let subkey = format!(r"SOFTWARE\Policies\Microsoft\Windows\QoS\{}", policy_name);
    unsafe {
        let subkey_w = to_wide_null(&subkey);
        let rc = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr());
        if rc == 0 || rc == 2 {
            Ok(())
        } else {
            Err(format!("Suppression QoS {} code {}", policy_name, rc))
        }
    }
}

pub fn set_launch_with_windows(enabled: bool, minimized: bool) -> Result<(), String> {
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const APP_VAL: &str = "WinBoost";
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey_w = to_wide_null(RUN_KEY);
        let rc = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if rc != 0 {
            return Err(format!("Ouverture clé Run impossible (code {})", rc));
        }
        let val_w = to_wide_null(APP_VAL);
        let res = if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let cmd = if minimized {
                format!("\"{}\" --minimized", exe.display())
            } else {
                format!("\"{}\"", exe.display())
            };
            let cmd_w = to_wide_null(&cmd);
            let rc2 = RegSetValueExW(
                hkey,
                val_w.as_ptr(),
                0,
                REG_SZ,
                cmd_w.as_ptr() as *const u8,
                (cmd_w.len() * 2) as u32,
            );
            if rc2 == 0 {
                Ok(())
            } else {
                Err(format!("Écriture démarrage Windows code {}", rc2))
            }
        } else {
            let rc2 = RegDeleteValueW(hkey, val_w.as_ptr());
            if rc2 == 0 || rc2 == 2 {
                Ok(())
            } else {
                Err(format!("Suppression démarrage Windows code {}", rc2))
            }
        };
        RegCloseKey(hkey);
        res
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ICMP PING NATIF IPv4 + IPv6 (ALIGNEMENT MÉMOIRE 8 OCTETS GARANTI)
// ═══════════════════════════════════════════════════════════════════════════

/// Tampon aligné sur 8 octets pour `ICMP_ECHO_REPLY` (évite tout UB de cast non aligné).
#[repr(C, align(8))]
struct AlignedIcmpV4ReplyBuf {
    data: [u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + 64],
}

/// Tampon aligné sur 8 octets pour `ICMPV6_ECHO_REPLY_LH`.
#[repr(C, align(8))]
struct AlignedIcmpV6ReplyBuf {
    data: [u8; std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + 64],
}

fn resolve_ping_ip(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim().trim_matches(['[', ']']);
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }
    let addrs: Vec<IpAddr> = (trimmed, 80u16)
        .to_socket_addrs()
        .ok()?
        .map(|sa| sa.ip())
        .collect();
    // Préfère IPv4 s'il existe, sinon bascule automatiquement sur IPv6
    addrs
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4())
        .or_else(|| addrs.into_iter().next())
}

fn ping_ipv4(ip: Ipv4Addr, count: u32) -> Result<Vec<f32>, String> {
    let dest_addr_u32 = u32::from_ne_bytes(ip.octets());
    let payload = [0x50u8; 32];
    let mut reply_buf = AlignedIcmpV4ReplyBuf {
        data: [0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + 64],
    };
    let mut rtts = Vec::with_capacity(count as usize);

    unsafe {
        let icmp_handle = IcmpCreateFile();
        if icmp_handle == INVALID_HANDLE_VALUE || icmp_handle.is_null() {
            return Err("IcmpCreateFile indisponible".to_string());
        }

        for _ in 0..count {
            reply_buf.data.fill(0);
            let replies = IcmpSendEcho(
                icmp_handle,
                dest_addr_u32,
                payload.as_ptr() as *const _,
                payload.len() as u16,
                null(),
                reply_buf.data.as_mut_ptr() as *mut _,
                reply_buf.data.len() as u32,
                1000,
            );
            if replies > 0 {
                // Alignement >= align_of::<ICMP_ECHO_REPLY>() garanti par #[repr(C, align(8))]
                let reply = &*(reply_buf.data.as_ptr() as *const ICMP_ECHO_REPLY);
                if reply.Status == 0 {
                    rtts.push(reply.RoundTripTime as f32);
                }
            }
        }
        IcmpCloseHandle(icmp_handle);
    }
    Ok(rtts)
}

fn ping_ipv6(ip: Ipv6Addr, count: u32) -> Result<Vec<f32>, String> {
    type Icmp6SendEcho2Fn = unsafe extern "system" fn(
        HANDLE,
        HANDLE,
        *const c_void,
        *const c_void,
        *const SOCKADDR_IN6,
        *const SOCKADDR_IN6,
        *const c_void,
        u16,
        *const c_void,
        *mut c_void,
        u32,
        u32,
    ) -> u32;

    let dll = SystemDll::load_system32("iphlpapi.dll")
        .ok_or_else(|| "iphlpapi.dll introuvable".to_string())?;
    let icmp6_send: Icmp6SendEcho2Fn = unsafe {
        let Some(ptr) = GetProcAddress(dll.0, b"Icmp6SendEcho2\0".as_ptr()) else {
            return Err("Icmp6SendEcho2 indisponible".to_string());
        };
        std::mem::transmute(ptr)
    };

    let payload = [0x50u8; 32];
    let mut reply_buf = AlignedIcmpV6ReplyBuf {
        data: [0u8; std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + 64],
    };
    let mut rtts = Vec::with_capacity(count as usize);

    let src = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: [0u8; 16] },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    };
    let dst = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: ip.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    };

    unsafe {
        let icmp_handle = Icmp6CreateFile();
        if icmp_handle == INVALID_HANDLE_VALUE || icmp_handle.is_null() {
            return Err("Icmp6CreateFile indisponible".to_string());
        }

        for _ in 0..count {
            reply_buf.data.fill(0);
            let replies = icmp6_send(
                icmp_handle,
                null_mut(),
                null(),
                null(),
                &src,
                &dst,
                payload.as_ptr() as *const _,
                payload.len() as u16,
                null(),
                reply_buf.data.as_mut_ptr() as *mut _,
                reply_buf.data.len() as u32,
                1000,
            );
            if replies > 0 {
                let reply = &*(reply_buf.data.as_ptr() as *const ICMPV6_ECHO_REPLY_LH);
                if reply.Status == 0 {
                    rtts.push(reply.RoundTripTime as f32);
                }
            }
        }
        IcmpCloseHandle(icmp_handle);
    }
    Ok(rtts)
}

/// Test de latence ICMP natif Windows IPv4 & IPv6 (`IcmpSendEcho` / `Icmp6SendEcho2`).
pub fn run_icmp_ping(target_name: &str, host: &str, count: u32) -> PingResult {
    let Some(ip) = resolve_ping_ip(host) else {
        return PingResult {
            target_name: target_name.to_string(),
            host: host.to_string(),
            resolved_ip: "Non résolu".to_string(),
            sent: count,
            received: 0,
            loss_percent: 100.0,
            min_ms: 0.0,
            avg_ms: 0.0,
            max_ms: 0.0,
            jitter_ms: 0.0,
            timestamp: Local::now(),
            error: Some("Résolution DNS impossible (hors-ligne ou hôte invalide)".to_string()),
        };
    };

    let ping_res = match ip {
        IpAddr::V4(v4) => ping_ipv4(v4, count),
        IpAddr::V6(v6) => ping_ipv6(v6, count),
    };

    let rtts = match ping_res {
        Ok(v) => v,
        Err(err) => {
            return PingResult {
                target_name: target_name.to_string(),
                host: host.to_string(),
                resolved_ip: ip.to_string(),
                sent: count,
                received: 0,
                loss_percent: 100.0,
                min_ms: 0.0,
                avg_ms: 0.0,
                max_ms: 0.0,
                jitter_ms: 0.0,
                timestamp: Local::now(),
                error: Some(err),
            };
        }
    };

    let received = rtts.len() as u32;
    let loss_percent = if count > 0 {
        ((count - received) as f32 / count as f32) * 100.0
    } else {
        0.0
    };

    if rtts.is_empty() {
        return PingResult {
            target_name: target_name.to_string(),
            host: host.to_string(),
            resolved_ip: ip.to_string(),
            sent: count,
            received: 0,
            loss_percent,
            min_ms: 0.0,
            avg_ms: 0.0,
            max_ms: 0.0,
            jitter_ms: 0.0,
            timestamp: Local::now(),
            error: Some("Aucune réponse ICMP (délai dépassé ou pare-feu)".to_string()),
        };
    }

    let min_ms = rtts.iter().copied().fold(f32::INFINITY, f32::min);
    let max_ms = rtts.iter().copied().fold(0.0f32, f32::max);
    let avg_ms = rtts.iter().sum::<f32>() / rtts.len() as f32;
    let jitter_ms = if rtts.len() >= 2 {
        let diffs: f32 = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        diffs / (rtts.len() - 1) as f32
    } else {
        0.0
    };

    PingResult {
        target_name: target_name.to_string(),
        host: host.to_string(),
        resolved_ip: ip.to_string(),
        sent: count,
        received,
        loss_percent,
        min_ms,
        avg_ms,
        max_ms,
        jitter_ms,
        timestamp: Local::now(),
        error: None,
    }
}

/// Retourne une description courte de la version de Windows.
pub fn detect_windows_label() -> String {
    let build = reg_read_string_hklm(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    )
    .and_then(|s| s.parse::<u32>().ok())
    .unwrap_or(0);
    if build >= 22000 {
        format!("Windows 11 (Build {})", build)
    } else if build > 0 {
        format!("Windows 10 (Build {})", build)
    } else {
        "Windows 10/11".to_string()
    }
}

fn reg_read_string_hklm(subkey: &str, value_name: &str) -> Option<String> {
    unsafe {
        let mut hkey: HKEY = null_mut();
        let subkey_w = to_wide_null(subkey);
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return None;
        }
        let val_w = to_wide_null(value_name);
        let mut buf = [0u16; 128];
        let mut buf_bytes = (buf.len() * 2) as u32;
        let mut val_type = 0u32;
        let rc = RegQueryValueExW(
            hkey,
            val_w.as_ptr(),
            null(),
            &mut val_type,
            buf.as_mut_ptr() as *mut u8,
            &mut buf_bytes,
        );
        RegCloseKey(hkey);
        if rc == 0 && val_type == REG_SZ {
            let chars = (buf_bytes as usize) / 2;
            let slice = &buf[..chars.min(buf.len())];
            let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            Some(String::from_utf16_lossy(&slice[..end]))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_powercfg_french_and_english() {
        let fr = "GUID du mode de gestion de l'alimentation : 381b4222-f694-41f0-9685-ff5bb260df2e  (Usage normal)\r\n";
        let (g, n) = parse_powercfg_guid_and_name(fr).unwrap();
        assert_eq!(g, "381b4222-f694-41f0-9685-ff5bb260df2e");
        assert_eq!(n, "Usage normal");

        let en = "Power Scheme GUID: e9a42b02-d5df-448d-aa00-03f14749eb61  (Ultimate Performance)\n";
        let (g2, n2) = parse_powercfg_guid_and_name(en).unwrap();
        assert_eq!(g2, "e9a42b02-d5df-448d-aa00-03f14749eb61");
        assert_eq!(n2, "Ultimate Performance");
    }

    #[test]
    fn test_guid_struct_roundtrip() {
        let g = parse_guid_struct(GUID_POWER_ULTIMATE).expect("GUID valide");
        assert_eq!(format_guid(&g), GUID_POWER_ULTIMATE);
        assert!(parse_guid_struct("not-a-guid").is_none());
    }

    #[test]
    fn test_aligned_icmp_buffers_satisfy_alignment() {
        assert!(
            std::mem::align_of::<AlignedIcmpV4ReplyBuf>() >= std::mem::align_of::<ICMP_ECHO_REPLY>()
        );
        assert!(
            std::mem::align_of::<AlignedIcmpV6ReplyBuf>()
                >= std::mem::align_of::<ICMPV6_ECHO_REPLY_LH>()
        );
    }

    #[test]
    fn test_ipv6_loopback_and_ipv4_loopback_ping() {
        let v4 = run_icmp_ping("Loopback IPv4", "127.0.0.1", 1);
        assert_eq!(v4.resolved_ip, "127.0.0.1");
        assert!(v4.error.is_none(), "Ping IPv4 loopback erreur: {:?}", v4.error);

        let v6 = run_icmp_ping("Loopback IPv6", "::1", 1);
        assert_eq!(v6.resolved_ip, "::1");
        assert!(v6.error.is_none(), "Ping IPv6 loopback erreur: {:?}", v6.error);
    }

    #[test]
    fn test_compute_safe_affinity_mask() {
        assert_eq!(compute_safe_affinity_mask(0xFF, true), Some(0xFE));
        assert_eq!(compute_safe_affinity_mask(0xFF, false), None);
        assert_eq!(compute_safe_affinity_mask(0b11, true), None);
    }

    #[test]
    fn test_security_guards_on_start_service_qos_and_registry() {
        // start_service doit refuser les services critiques
        assert!(start_service("RpcSs").is_err());
        assert!(start_service("vgc").is_err());
        assert!(start_service("../bad").is_err());

        // QoS doit refuser tout nom ne commençant pas par WinBoost_
        assert!(remove_qos_dscp_policy("OtherVendorPolicy").is_err());
        assert!(remove_qos_dscp_policy(r"WinBoost_..\System").is_err());

        // Registry restore doit refuser toute clé hors allowlist
        let evil = RegistryRecoveryRecord {
            hive: "HKLM".to_string(),
            subkey: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value_name: "Backdoor".to_string(),
            existed_before: true,
            previous_dword: Some(1),
        };
        assert!(restore_registry_record(&evil).is_err());
    }
}
