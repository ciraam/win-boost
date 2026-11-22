//! Monitoring matériel léger en temps réel (CPU, RAM, GPU, Températures, Empreinte App).
//!
//! Conçu pour un impact quasi nul et une sécurité renforcée :
//! - Utilise directement les APIs Win32 natives (`GetSystemTimes`, `GlobalMemoryStatusEx`).
//! - Charge `nvml.dll` de façon protégée contre le DLL Hijacking (`LoadLibraryExW` avec
//!   `LOAD_LIBRARY_SEARCH_SYSTEM32` puis chemins absolus vérifiés System32/NVSMI) et libère
//!   systématiquement le module via `FreeLibrary` en cas d'échec ou dans `Drop`.
//! - Mis totalement en pause lorsque la fenêtre est réduite dans le System Tray.

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{FreeLibrary, FILETIME, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetSystemTimes};

use crate::models::SystemMetrics;
use crate::win32_ops::to_wide_null;

const HISTORY_CAPACITY: usize = 60;

#[repr(C)]
struct NvmlUtilization {
    gpu: c_uint,
    memory: c_uint,
}

#[repr(C)]
struct NvmlMemory {
    total: u64,
    free: u64,
    used: u64,
}

type NvmlInitFn = unsafe extern "C" fn() -> c_int;
type NvmlShutdownFn = unsafe extern "C" fn() -> c_int;
type NvmlGetHandleByIndexFn = unsafe extern "C" fn(c_uint, *mut *mut c_void) -> c_int;
type NvmlGetUtilFn = unsafe extern "C" fn(*mut c_void, *mut NvmlUtilization) -> c_int;
type NvmlGetTempFn = unsafe extern "C" fn(*mut c_void, c_uint, *mut c_uint) -> c_int;
type NvmlGetMemFn = unsafe extern "C" fn(*mut c_void, *mut NvmlMemory) -> c_int;
type NvmlGetNameFn = unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint) -> c_int;

/// Garde RAII assurant que `FreeLibrary` est toujours appelé si l'initialisation NVML échoue.
struct OwnedModule(HMODULE);

impl OwnedModule {
    fn raw(&self) -> HMODULE {
        self.0
    }

    fn into_raw(self) -> HMODULE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for OwnedModule {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }
}

/// Charge `nvml.dll` en toute sécurité contre le DLL Hijacking :
/// 1. `System32` uniquement via `LOAD_LIBRARY_SEARCH_SYSTEM32`
/// 2. Chemins absolus système vérifiés (`System32\nvml.dll`, `Program Files\NVIDIA Corporation\NVSMI\nvml.dll`)
///    sans jamais rechercher dans le répertoire courant ni le dossier de l'application.
fn load_nvml_module_safe() -> Option<OwnedModule> {
    unsafe {
        // 1. Recherche restreinte à System32 (protection stricte contre le DLL Hijacking)
        let sys32_name = to_wide_null("nvml.dll");
        let h = LoadLibraryExW(
            sys32_name.as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if !h.is_null() {
            return Some(OwnedModule(h));
        }

        // 2. Chemins absolus système de confiance uniquement
        let trusted_paths = [
            r"C:\Windows\System32\nvml.dll",
            r"C:\Program Files\NVIDIA Corporation\NVSMI\nvml.dll",
        ];
        for path_str in trusted_paths {
            if !Path::new(path_str).is_file() {
                continue;
            }
            let w = to_wide_null(path_str);
            let h = LoadLibraryExW(
                w.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if !h.is_null() {
                return Some(OwnedModule(h));
            }
        }

        None
    }
}

struct NvmlProbe {
    module: HMODULE,
    device: *mut c_void,
    gpu_name: String,
    get_util: NvmlGetUtilFn,
    get_temp: NvmlGetTempFn,
    get_mem: NvmlGetMemFn,
    shutdown: NvmlShutdownFn,
}

// Les pointeurs de fonctions NVML sont thread-safe en lecture
unsafe impl Send for NvmlProbe {}

impl NvmlProbe {
    fn try_load() -> Option<Self> {
        let module_guard = load_nvml_module_safe()?;
        let module = module_guard.raw();

        unsafe {
            let init: NvmlInitFn = std::mem::transmute(
                GetProcAddress(module, b"nvmlInit_v2\0".as_ptr())
                    .or_else(|| GetProcAddress(module, b"nvmlInit\0".as_ptr()))?,
            );
            let shutdown: NvmlShutdownFn =
                std::mem::transmute(GetProcAddress(module, b"nvmlShutdown\0".as_ptr())?);
            let get_handle: NvmlGetHandleByIndexFn = std::mem::transmute(
                GetProcAddress(module, b"nvmlDeviceGetHandleByIndex_v2\0".as_ptr())
                    .or_else(|| GetProcAddress(module, b"nvmlDeviceGetHandleByIndex\0".as_ptr()))?,
            );
            let get_util: NvmlGetUtilFn = std::mem::transmute(GetProcAddress(
                module,
                b"nvmlDeviceGetUtilizationRates\0".as_ptr(),
            )?);
            let get_temp: NvmlGetTempFn = std::mem::transmute(GetProcAddress(
                module,
                b"nvmlDeviceGetTemperature\0".as_ptr(),
            )?);
            let get_mem: NvmlGetMemFn = std::mem::transmute(GetProcAddress(
                module,
                b"nvmlDeviceGetMemoryInfo\0".as_ptr(),
            )?);
            let get_name: Option<NvmlGetNameFn> =
                GetProcAddress(module, b"nvmlDeviceGetName\0".as_ptr())
                    .map(|p| std::mem::transmute(p));

            // Si init échoue, `module_guard` appelle automatiquement `FreeLibrary`.
            if init() != 0 {
                return None;
            }

            let mut device: *mut c_void = null_mut();
            if get_handle(0, &mut device) != 0 || device.is_null() {
                shutdown();
                // `module_guard` libère la DLL via `FreeLibrary` à la sortie
                return None;
            }

            let mut gpu_name = "NVIDIA GPU".to_string();
            if let Some(fn_name) = get_name {
                let mut buf = [0 as c_char; 96];
                if fn_name(device, buf.as_mut_ptr(), buf.len() as u32) == 0 {
                    if let Ok(s) = CStr::from_ptr(buf.as_ptr()).to_str() {
                        gpu_name = s.to_string();
                    }
                }
            }

            Some(Self {
                module: module_guard.into_raw(),
                device,
                gpu_name,
                get_util,
                get_temp,
                get_mem,
                shutdown,
            })
        }
    }

    fn sample(&self) -> (Option<f32>, Option<f32>, Option<u64>, Option<u64>) {
        unsafe {
            let mut util = NvmlUtilization { gpu: 0, memory: 0 };
            let gpu_pct = if (self.get_util)(self.device, &mut util) == 0 {
                Some(util.gpu as f32)
            } else {
                None
            };

            let mut temp: c_uint = 0;
            // NVML_TEMPERATURE_GPU = 0
            let gpu_temp = if (self.get_temp)(self.device, 0, &mut temp) == 0 {
                Some(temp as f32)
            } else {
                None
            };

            let mut mem = NvmlMemory {
                total: 0,
                free: 0,
                used: 0,
            };
            let (vram_used, vram_total) = if (self.get_mem)(self.device, &mut mem) == 0 {
                (Some(mem.used / (1024 * 1024)), Some(mem.total / (1024 * 1024)))
            } else {
                (None, None)
            };

            (gpu_pct, gpu_temp, vram_used, vram_total)
        }
    }
}

impl Drop for NvmlProbe {
    fn drop(&mut self) {
        unsafe {
            (self.shutdown)();
            if !self.module.is_null() {
                FreeLibrary(self.module);
                self.module = null_mut();
            }
        }
    }
}

fn ft_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Collecteur de métriques léger avec historique circulaire pour les courbes.
pub struct SystemMonitor {
    prev_idle: u64,
    prev_kernel: u64,
    prev_user: u64,
    nvml: Option<NvmlProbe>,
    pub current: SystemMetrics,
    pub cpu_history: VecDeque<f32>,
    pub ram_history: VecDeque<f32>,
    pub gpu_history: VecDeque<f32>,
    pub ping_history: VecDeque<f32>,
    pub gpu_name: String,
    pub paused: bool,
}

impl SystemMonitor {
    pub fn new() -> Self {
        let nvml = NvmlProbe::try_load();
        let gpu_name = nvml
            .as_ref()
            .map(|n| n.gpu_name.clone())
            .unwrap_or_else(|| "GPU Windows (DirectX / WDDM)".to_string());

        let (idle, kernel, user) = read_system_times();
        let mut mon = Self {
            prev_idle: idle,
            prev_kernel: kernel,
            prev_user: user,
            nvml,
            current: SystemMetrics::default(),
            cpu_history: VecDeque::with_capacity(HISTORY_CAPACITY),
            ram_history: VecDeque::with_capacity(HISTORY_CAPACITY),
            gpu_history: VecDeque::with_capacity(HISTORY_CAPACITY),
            ping_history: VecDeque::with_capacity(HISTORY_CAPACITY),
            gpu_name,
            paused: false,
        };
        mon.sample();
        mon
    }

    /// Met à jour les compteurs CPU, RAM, GPU et empreinte RAM de WinBoost.
    /// Ne fait rien lorsque `paused == true` (fenêtre réduite dans le System Tray).
    pub fn sample(&mut self) {
        if self.paused {
            return;
        }

        // 1. CPU % par delta GetSystemTimes
        let (idle, kernel, user) = read_system_times();
        let d_idle = idle.saturating_sub(self.prev_idle);
        let d_kernel = kernel.saturating_sub(self.prev_kernel);
        let d_user = user.saturating_sub(self.prev_user);
        let total = d_kernel.saturating_add(d_user);
        if total > 0 {
            let busy = total.saturating_sub(d_idle);
            self.current.cpu_usage_percent =
                ((busy as f64 / total as f64) * 100.0).clamp(0.0, 100.0) as f32;
        }
        self.prev_idle = idle;
        self.prev_kernel = kernel;
        self.prev_user = user;

        // 2. RAM globale via GlobalMemoryStatusEx
        let (used_gb, free_gb, total_gb, ram_pct) = read_memory_status();
        self.current.ram_used_gb = used_gb;
        self.current.ram_free_gb = free_gb;
        self.current.ram_total_gb = total_gb;
        self.current.ram_usage_percent = ram_pct;

        // 3. Empreinte mémoire de WinBoost lui-même
        self.current.app_ram_mb = read_self_ram_mb();

        // 4. GPU & Température via NVML si disponible
        if let Some(nvml) = &self.nvml {
            let (gpu_pct, gpu_temp, vram_used, vram_total) = nvml.sample();
            self.current.gpu_usage_percent = gpu_pct;
            self.current.gpu_temp_c = gpu_temp;
            self.current.gpu_vram_used_mb = vram_used;
            self.current.gpu_vram_total_mb = vram_total;
        }

        push_ring(&mut self.cpu_history, self.current.cpu_usage_percent);
        push_ring(&mut self.ram_history, self.current.ram_usage_percent);
        if let Some(g) = self.current.gpu_usage_percent {
            push_ring(&mut self.gpu_history, g);
        }
    }

    pub fn record_ping_ms(&mut self, ms: f32) {
        self.current.net_latency_ms = Some(ms);
        push_ring(&mut self.ping_history, ms);
    }

    pub fn available_ram_mb() -> u64 {
        let (_, free_gb, _, _) = read_memory_status();
        (free_gb * 1024.0) as u64
    }
}

fn push_ring(q: &mut VecDeque<f32>, val: f32) {
    if q.len() >= HISTORY_CAPACITY {
        q.pop_front();
    }
    q.push_back(val);
}

fn read_system_times() -> (u64, u64, u64) {
    unsafe {
        let mut idle: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        if GetSystemTimes(&mut idle, &mut kernel, &mut user) != 0 {
            (ft_u64(idle), ft_u64(kernel), ft_u64(user))
        } else {
            (0, 0, 0)
        }
    }
}

pub fn read_memory_status() -> (f32, f32, f32, f32) {
    unsafe {
        let mut mem: MEMORYSTATUSEX = std::mem::zeroed();
        mem.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut mem) != 0 && mem.ullTotalPhys > 0 {
            let total_gb = mem.ullTotalPhys as f64 / (1024.0 * 1024.0 * 1024.0);
            let free_gb = mem.ullAvailPhys as f64 / (1024.0 * 1024.0 * 1024.0);
            let used_gb = (total_gb - free_gb).max(0.0);
            let pct = ((used_gb / total_gb) * 100.0).clamp(0.0, 100.0);
            return (used_gb as f32, free_gb as f32, total_gb as f32, pct as f32);
        }
        (0.0, 0.0, 0.0, 0.0)
    }
}

pub fn read_self_ram_mb() -> f32 {
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
            return (pmc.WorkingSetSize as f64 / (1024.0 * 1024.0)) as f32;
        }
        0.0
    }
}
