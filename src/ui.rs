//! Interface bureau native Win32 + Direct2D (`ID2D1HwndRenderTarget`) + DirectWrite (`IDWriteTextFormat`).
//!
//! Zéro `eframe`, zéro `egui`, zéro `glow`/OpenGL, zéro contexte GPU/VRAM :
//! - Rendu Direct2D logiciel anti-aliasé (`D2D1_RENDER_TARGET_TYPE_SOFTWARE`) : < 20 Mo RAM fenêtre ouverte.
//! - DPI PerMonitorV2, barre de titre sombre DWM Windows 10/11, double-buffering sans scintillement.
//! - Thème sombre OLED Cyber-Tactique (`#0B0F17`, cartes `#121826`, bordures `#1E293B`), 6 onglets complets,
//!   jauges circulaires animées CPU/RAM/GPU, courbes temps réel et icônes vectorielles Direct2D.
//! - Communication typée par Named Pipe (`\\.\pipe\WinBoost`) avec `winboost-svc.exe`.

use std::cell::RefCell;
use std::f32::consts::PI;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::core::{w, Interface, PCWSTR, PWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Direct2D::Common::{
    D2D1_ALPHA_MODE_IGNORE, D2D1_ALPHA_MODE_PREMULTIPLIED, D2D1_COLOR_F, D2D1_FIGURE_BEGIN_FILLED,
    D2D1_FIGURE_BEGIN_HOLLOW, D2D1_FIGURE_END_CLOSED, D2D1_FIGURE_END_OPEN, D2D1_PIXEL_FORMAT,
    D2D_POINT_2F, D2D_RECT_F, D2D_SIZE_F, D2D_SIZE_U,
};
use windows::Win32::Graphics::Direct2D::{
    D2D1CreateFactory, ID2D1DCRenderTarget, ID2D1Factory, ID2D1HwndRenderTarget,
    ID2D1RenderTarget, ID2D1SolidColorBrush, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE, D2D1_ARC_SEGMENT,
    D2D1_ARC_SIZE_LARGE, D2D1_ARC_SIZE_SMALL, D2D1_DRAW_TEXT_OPTIONS_CLIP, D2D1_ELLIPSE,
    D2D1_FACTORY_TYPE_SINGLE_THREADED, D2D1_HWND_RENDER_TARGET_PROPERTIES,
    D2D1_PRESENT_OPTIONS_NONE, D2D1_RENDER_TARGET_PROPERTIES, D2D1_RENDER_TARGET_TYPE_SOFTWARE,
    D2D1_ROUNDED_RECT, D2D1_SWEEP_DIRECTION_CLOCKWISE,
};
use windows::Win32::Graphics::DirectWrite::{
    DWriteCreateFactory, IDWriteFactory, IDWriteTextFormat, DWRITE_FACTORY_TYPE_SHARED,
    DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_WEIGHT_BOLD,
    DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_WEIGHT_SEMI_BOLD, DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
    DWRITE_PARAGRAPH_ALIGNMENT_NEAR, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_TEXT_ALIGNMENT_LEADING,
    DWRITE_TEXT_ALIGNMENT_TRAILING, DWRITE_WORD_WRAPPING_NO_WRAP, DWRITE_WORD_WRAPPING_WRAP,
};
use windows::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateCompatibleDC, CreateDIBSection, CreateSolidBrush, DeleteDC, DeleteObject,
    EndPaint, InvalidateRect, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
    PAINTSTRUCT,
};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows::Win32::UI::HiDpi::{
    GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    KillTimer, LoadCursorW, PostQuitMessage, RegisterClassExW, SetCursor, SetTimer, SetWindowPos,
    ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, HWND_BOTTOM, IDC_ARROW,
    IDC_HAND, MSG, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SW_SHOW, SW_SHOWNOACTIVATE,
    WM_CHAR, WM_CLOSE, WM_DESTROY, WM_DPICHANGED, WM_ERASEBKGND, WM_KEYDOWN, WM_LBUTTONDOWN,
    WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_PAINT, WM_SIZE, WM_TIMER, WNDCLASSEXW, WS_OVERLAPPEDWINDOW,
};

use crate::cleaner::{self, CleanCategoryId};
use crate::ipc::{handle_ipc_request, IpcClient, IpcRequest, IpcResponse, ServiceBackend, UiStateSnapshot};
use crate::models::{AppConfig, LogLevel, ProcessAction, ProfileId};
use crate::recovery::RecoveryState;
use crate::whitelist::immutable_whitelist_summary;
use crate::win32_ops::{self, SingleInstanceGuard, WinServiceState, MAIN_WINDOW_TITLE};

// ═══════════════════════════════════════════════════════════════════════════
// PALETTE CRAFT.RO DESIGN SYSTEM (Linear / Raycast / Setapp)
// ═══════════════════════════════════════════════════════════════════════════
const fn rgba(r: u8, g: u8, b: u8, a: f32) -> D2D1_COLOR_F {
    D2D1_COLOR_F {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a,
    }
}

const BG_OLED: D2D1_COLOR_F = rgba(11, 12, 14, 1.0); // #0B0C0E (--background)
const BG_SIDEBAR: D2D1_COLOR_F = rgba(17, 18, 21, 1.0); // #111215 (--sidebar)
const BG_CARD: D2D1_COLOR_F = rgba(22, 24, 29, 1.0); // #16181D (--card)
const BG_CARD_ELEVATED: D2D1_COLOR_F = rgba(28, 31, 38, 1.0); // #1C1F26 (Surface Hover)
const BG_CARD_ACTIVE_BOOST: D2D1_COLOR_F = rgba(16, 28, 26, 1.0);
const BORDER_SUBTLE: D2D1_COLOR_F = rgba(255, 255, 255, 0.08); // Hairline 1px Craft.ro
const BORDER_BRIGHT: D2D1_COLOR_F = rgba(255, 255, 255, 0.16); // Hover / Focus Craft.ro
const BORDER_ZENITHAL: D2D1_COLOR_F = rgba(255, 255, 255, 0.04); // Reflet supérieur interne
const TEXT_PRIMARY: D2D1_COLOR_F = rgba(244, 245, 247, 1.0); // #F4F5F7 (--foreground)
const TEXT_SECONDARY: D2D1_COLOR_F = rgba(138, 143, 152, 1.0); // #8A8F98 (--muted-foreground)
const TEXT_DARK: D2D1_COLOR_F = rgba(11, 12, 14, 1.0);
const ACCENT_EMERALD: D2D1_COLOR_F = rgba(16, 185, 129, 1.0); // #10B981 (Succès)
const ACCENT_CYAN: D2D1_COLOR_F = rgba(56, 189, 248, 1.0); // #38BDF8 (Info)
const ACCENT_INDIGO: D2D1_COLOR_F = rgba(94, 106, 210, 1.0); // #5E6AD2 (Primaire Craft.ro)
const ACCENT_AMBER: D2D1_COLOR_F = rgba(245, 158, 11, 1.0); // #F59E0B (Avertissement)
const ACCENT_CRIMSON: D2D1_COLOR_F = rgba(229, 72, 77, 1.0); // #E5484D (Destructif)

const TIMER_ANIM_ID: usize = 1;
const TIMER_POLL_ID: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Dashboard,
    GamesProfiles,
    ProcessesServices,
    PcCleaner,
    Monitoring,
    SettingsLogs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcSubTab {
    ManagedRules,
    WindowsServices,
    RunningProcesses,
    Whitelist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NavIcon {
    Bolt,
    Gamepad,
    Layers,
    SparkClean,
    Pulse,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusedInput {
    None,
    CustomPingHost,
    NewWhitelistExe,
    NewGameExe,
}

#[derive(Debug, Clone)]
enum UiAction {
    SwitchTab(ActiveTab),
    SwitchProcSubTab(ProcSubTab),
    ToggleBoost,
    SelectProfile(ProfileId),
    ToggleAutoBoost,
    QuickCleanRam,
    OpenCleanerAndScan,
    QuickPing(String, String),
    RelaunchAdmin,
    BrowseAndAddGameExe,
    SubmitNewGameExe,
    ToggleGameAuto(String, bool),
    CycleGameProfile(String),
    ToggleGameAvoidCore0(String),
    RemoveGame(String),
    CycleProcRule(String),
    ToggleServicePause(String, bool),
    AddWhitelist(String),
    RemoveWhitelist(String),
    SubmitNewWhitelist,
    ToggleCleanCat(CleanCategoryId),
    ScanClean,
    ExecuteClean,
    FocusField(FocusedInput),
    TriggerCustomPing,
    ToggleSettingLaunchWindows,
    ToggleSettingStartMin,
    ToggleSettingAutoCrash,
    SaveSnapshot,
    RestoreInitial,
    ExecuteCrashRecovery,
    SetLogFilter(Option<LogLevel>),
    ClearLogs,
    DismissBanner,
}

#[derive(Debug, Clone)]
struct HitRegion {
    id: u32,
    rect: D2D_RECT_F,
    action: UiAction,
}

/// Transport abstrait : Named Pipe vers `winboost-svc.exe` en production, ou backend local intégré
/// lors du mode `--screenshot` isolé.
enum BackendTransport {
    Pipe(IpcClient),
    Local(Arc<Mutex<ServiceBackend>>),
}

impl BackendTransport {
    fn send(&self, req: IpcRequest) -> Result<IpcResponse, String> {
        match self {
            BackendTransport::Pipe(client) => client.send(&req),
            BackendTransport::Local(backend) => Ok(handle_ipc_request(backend, req)),
        }
    }
}

struct Typography {
    title_lg: IDWriteTextFormat,
    title_md: IDWriteTextFormat,
    heading: IDWriteTextFormat,
    body: IDWriteTextFormat,
    body_bold: IDWriteTextFormat,
    small: IDWriteTextFormat,
    eyebrow: IDWriteTextFormat,
    mono: IDWriteTextFormat,
    kpi: IDWriteTextFormat,
    center_btn: IDWriteTextFormat,
    center_gauge: IDWriteTextFormat,
    right_body: IDWriteTextFormat,
    right_small: IDWriteTextFormat,
}

impl Typography {
    fn create(dw: &IDWriteFactory) -> windows::core::Result<Self> {
        let make = |family: PCWSTR,
                    weight,
                    size: f32,
                    align,
                    valign,
                    wrap|
         -> windows::core::Result<IDWriteTextFormat> {
            unsafe {
                let fmt = dw.CreateTextFormat(
                    family,
                    None,
                    weight,
                    DWRITE_FONT_STYLE_NORMAL,
                    DWRITE_FONT_STRETCH_NORMAL,
                    size,
                    w!("fr-FR"),
                )?;
                fmt.SetTextAlignment(align)?;
                fmt.SetParagraphAlignment(valign)?;
                fmt.SetWordWrapping(wrap)?;
                Ok(fmt)
            }
        };

        Ok(Self {
            title_lg: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_BOLD,
                21.0,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            title_md: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_BOLD,
                16.0,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            heading: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_SEMI_BOLD,
                13.5,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            body: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_NORMAL,
                12.5,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
                DWRITE_WORD_WRAPPING_WRAP,
            )?,
            body_bold: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_SEMI_BOLD,
                12.5,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            small: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_NORMAL,
                11.2,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
                DWRITE_WORD_WRAPPING_WRAP,
            )?,
            eyebrow: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_BOLD,
                10.2,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            mono: make(
                w!("Consolas"),
                DWRITE_FONT_WEIGHT_NORMAL,
                11.5,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            kpi: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_BOLD,
                22.0,
                DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            center_btn: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_BOLD,
                12.5,
                DWRITE_TEXT_ALIGNMENT_CENTER,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            center_gauge: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_BOLD,
                12.0,
                DWRITE_TEXT_ALIGNMENT_CENTER,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            right_body: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_SEMI_BOLD,
                12.0,
                DWRITE_TEXT_ALIGNMENT_TRAILING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
            right_small: make(
                w!("Segoe UI"),
                DWRITE_FONT_WEIGHT_NORMAL,
                11.0,
                DWRITE_TEXT_ALIGNMENT_TRAILING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER,
                DWRITE_WORD_WRAPPING_NO_WRAP,
            )?,
        })
    }
}

struct NativeUiState {
    hwnd: HWND,
    dpi_scale: f32,
    width_dip: f32,
    height_dip: f32,
    d2d_factory: ID2D1Factory,
    render_target: Option<ID2D1HwndRenderTarget>,
    typo: Typography,

    transport: BackendTransport,
    instance_guard: Option<SingleInstanceGuard>,
    state: UiStateSnapshot,
    ui_ram_mb: f32,

    active_tab: ActiveTab,
    proc_sub_tab: ProcSubTab,
    scroll_y: f32,
    max_scroll_y: f32,
    log_filter: Option<LogLevel>,
    banner: Option<(String, D2D1_COLOR_F, Instant)>,

    // Champs texte interactifs
    focused_input: FocusedInput,
    ping_host_input: String,
    new_whitelist_input: String,
    new_game_input: String,

    // Animations fluides (jauges radiales, barres, scan)
    anim_cpu: f32,
    anim_ram: f32,
    anim_gpu: f32,
    anim_phase: f32,
    hovered_id: Option<u32>,
    hit_regions: Vec<HitRegion>,
    next_hit_id: u32,

    // Mode capture automatisée (`--screenshot <file.png>`)
    screenshot_target: Option<PathBuf>,
    screenshot_frames: u32,
    screenshot_saved: bool,
    trimmed_once: bool,
}

thread_local! {
    static APP_STATE: RefCell<Option<Box<NativeUiState>>> = const { RefCell::new(None) };
}

/// Vérifie que Direct2D et DirectWrite s'initialisent proprement (utilisé par `--self-test`).
pub fn verify_direct2d_available() -> Result<(), String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let d2d: ID2D1Factory = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)
            .map_err(|e| format!("D2D1CreateFactory: {}", e))?;
        let dw: IDWriteFactory = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)
            .map_err(|e| format!("DWriteCreateFactory: {}", e))?;
        let _typo = Typography::create(&dw).map_err(|e| format!("Typography: {}", e))?;
        drop(d2d);
        CoUninitialize();
    }
    Ok(())
}

/// Point d'entrée de la fenêtre native Win32 + Direct2D + DirectWrite.
pub fn run_native_ui(
    instance_guard: Option<SingleInstanceGuard>,
    use_ipc: bool,
    screenshot_target: Option<PathBuf>,
) -> Result<(), String> {
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }

    let d2d_factory: ID2D1Factory = unsafe {
        D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, None)
            .map_err(|e| format!("D2D1CreateFactory échec: {}", e))?
    };
    let dwrite_factory: IDWriteFactory = unsafe {
        DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)
            .map_err(|e| format!("DWriteCreateFactory échec: {}", e))?
    };
    let typo =
        Typography::create(&dwrite_factory).map_err(|e| format!("DirectWrite init échec: {}", e))?;

    let transport = if use_ipc {
        BackendTransport::Pipe(IpcClient::default_pipe())
    } else {
        let cfg = AppConfig::load_or_default();
        let mut backend = ServiceBackend::new(cfg, RecoveryState::default_path());
        backend.monitor.paused = false;
        for _ in 0..14 {
            backend.monitor.sample();
        }
        BackendTransport::Local(Arc::new(Mutex::new(backend)))
    };

    let initial_snapshot = match transport.send(IpcRequest::GetState {
        include_processes: false,
    }) {
        Ok(IpcResponse::State { snapshot }) => *snapshot,
        _ => {
            let mut b = ServiceBackend::new(AppConfig::default(), RecoveryState::default_path());
            b.build_snapshot(false)
        }
    };

    let hinstance = unsafe { GetModuleHandleW(None).map_err(|e| e.to_string())? };
    let class_name = w!("WinBoostD2DWindowClass");
    let bg_brush = unsafe { CreateSolidBrush(COLORREF(0x0017_0F0B)) }; // #0B0F17 en BGR

    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wnd_proc),
        hInstance: hinstance.into(),
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
        hbrBackground: bg_brush,
        lpszClassName: class_name,
        ..Default::default()
    };
    unsafe {
        RegisterClassExW(&wc);
    }

    let title_w = win32_ops::to_wide_null(MAIN_WINDOW_TITLE);
    let hwnd = unsafe {
        CreateWindowExW(
            Default::default(),
            class_name,
            PCWSTR(title_w.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1240,
            780,
            None,
            None,
            HINSTANCE::from(hinstance),
            None,
        )
        .map_err(|e| format!("CreateWindowExW échec: {}", e))?
    };

    // Ajuste la fenêtre au DPI actif pour garantir un espace client confortable (>= 1160x720 DIP)
    let dpi = unsafe { GetDpiForWindow(hwnd).max(96) as f32 };
    let dpi_scale = dpi / 96.0;
    unsafe {
        let target_w = (1180.0 * dpi_scale).round() as i32;
        let target_h = (740.0 * dpi_scale).round() as i32;
        let _ = SetWindowPos(
            hwnd,
            HWND::default(),
            0,
            0,
            target_w,
            target_h,
            SWP_NOACTIVATE | SWP_NOMOVE,
        );
    }

    // Barre de titre sombre native Windows 10/11
    unsafe {
        let dark: u32 = 1;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
        );
    }

    let mut rc = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut rc);
    }

    let init_cpu = initial_snapshot.metrics.cpu_usage_percent;
    let init_ram = initial_snapshot.metrics.ram_usage_percent;
    let init_gpu = initial_snapshot.metrics.gpu_usage_percent.unwrap_or(0.0);
    let init_ping_host = initial_snapshot.config.ping_custom_host.clone();

    let state = Box::new(NativeUiState {
        hwnd,
        dpi_scale,
        width_dip: (rc.right - rc.left).max(1) as f32 / dpi_scale,
        height_dip: (rc.bottom - rc.top).max(1) as f32 / dpi_scale,
        d2d_factory,
        render_target: None,
        typo,
        transport,
        instance_guard,
        state: initial_snapshot,
        ui_ram_mb: crate::monitoring::read_self_ram_mb(),
        active_tab: ActiveTab::Dashboard,
        proc_sub_tab: ProcSubTab::ManagedRules,
        scroll_y: 0.0,
        max_scroll_y: 0.0,
        log_filter: None,
        banner: None,
        focused_input: FocusedInput::None,
        ping_host_input: init_ping_host,
        new_whitelist_input: String::new(),
        new_game_input: String::new(),
        anim_cpu: init_cpu,
        anim_ram: init_ram,
        anim_gpu: init_gpu,
        anim_phase: 0.0,
        hovered_id: None,
        hit_regions: Vec::with_capacity(96),
        next_hit_id: 1,
        screenshot_target: screenshot_target.clone(),
        screenshot_frames: 0,
        screenshot_saved: false,
        trimmed_once: false,
    });

    APP_STATE.with(|cell| {
        *cell.borrow_mut() = Some(state);
    });

    unsafe {
        if screenshot_target.is_some() {
            // Mode --screenshot : ouvre sans voler le focus et à l'arrière-plan sous Windows
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            let _ = SetWindowPos(
                hwnd,
                HWND_BOTTOM,
                0,
                0,
                0,
                0,
                SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE,
            );
            SetTimer(hwnd, TIMER_ANIM_ID, 16, None);
        } else {
            let _ = ShowWindow(hwnd, SW_SHOW);
            SetTimer(hwnd, TIMER_ANIM_ID, 33, None);
            SetTimer(hwnd, TIMER_POLL_ID, 1000, None);
        }
        let _ = InvalidateRect(hwnd, None, false);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let _ = DeleteObject(bg_brush);
    }

    APP_STATE.with(|cell| {
        *cell.borrow_mut() = None;
    });
    unsafe {
        CoUninitialize();
    }
    Ok(())
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => LRESULT(1),
        WM_SIZE => {
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.on_resize();
                }
            });
            LRESULT(0)
        }
        WM_DPICHANGED => {
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    let dpi = GetDpiForWindow(hwnd).max(96) as f32;
                    app.dpi_scale = dpi / 96.0;
                    app.render_target = None;
                    app.on_resize();
                }
            });
            LRESULT(0)
        }
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let _hdc = BeginPaint(hwnd, &mut ps);
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.paint_window();
                }
            });
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_TIMER => {
            let timer_id = wparam.0;
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.on_timer(timer_id);
                }
            });
            LRESULT(0)
        }
        WM_MOUSEMOVE => {
            let x_px = (lparam.0 & 0xFFFF) as i16 as f32;
            let y_px = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.on_mouse_move(x_px, y_px);
                }
            });
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            let x_px = (lparam.0 & 0xFFFF) as i16 as f32;
            let y_px = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.on_click(x_px, y_px);
                }
            });
            LRESULT(0)
        }
        WM_MOUSEWHEEL => {
            let delta = ((wparam.0 >> 16) & 0xFFFF) as i16 as f32;
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.on_scroll(delta);
                }
            });
            LRESULT(0)
        }
        WM_CHAR => {
            let ch = char::from_u32(wparam.0 as u32);
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    if let Some(c) = ch {
                        app.on_char(c);
                    }
                }
            });
            LRESULT(0)
        }
        WM_KEYDOWN => {
            let vk = wparam.0 as u32;
            APP_STATE.with(|cell| {
                if let Some(app) = cell.borrow_mut().as_mut() {
                    app.on_key_down(vk);
                }
            });
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = KillTimer(hwnd, TIMER_ANIM_ID);
            let _ = KillTimer(hwnd, TIMER_POLL_ID);
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

impl NativeUiState {
    fn on_resize(&mut self) {
        let mut rc = RECT::default();
        unsafe {
            let _ = GetClientRect(self.hwnd, &mut rc);
        }
        let w_px = (rc.right - rc.left).max(1) as u32;
        let h_px = (rc.bottom - rc.top).max(1) as u32;
        self.width_dip = w_px as f32 / self.dpi_scale;
        self.height_dip = h_px as f32 / self.dpi_scale;
        if let Some(ref rt) = self.render_target {
            let _ = unsafe {
                rt.Resize(&D2D_SIZE_U {
                    width: w_px,
                    height: h_px,
                })
            };
        }
        self.request_redraw();
    }

    fn request_redraw(&self) {
        unsafe {
            let _ = InvalidateRect(self.hwnd, None, false);
        }
    }

    fn ensure_render_target(&mut self) -> Option<ID2D1HwndRenderTarget> {
        if let Some(ref rt) = self.render_target {
            return Some(rt.clone());
        }
        let mut rc = RECT::default();
        unsafe {
            let _ = GetClientRect(self.hwnd, &mut rc);
        }
        let w_px = (rc.right - rc.left).max(1) as u32;
        let h_px = (rc.bottom - rc.top).max(1) as u32;
        let dpi = self.dpi_scale * 96.0;

        let rt_props = D2D1_RENDER_TARGET_PROPERTIES {
            r#type: D2D1_RENDER_TARGET_TYPE_SOFTWARE,
            pixelFormat: D2D1_PIXEL_FORMAT {
                format: DXGI_FORMAT_B8G8R8A8_UNORM,
                alphaMode: D2D1_ALPHA_MODE_IGNORE,
            },
            dpiX: dpi,
            dpiY: dpi,
            ..Default::default()
        };
        let hwnd_props = D2D1_HWND_RENDER_TARGET_PROPERTIES {
            hwnd: self.hwnd,
            pixelSize: D2D_SIZE_U {
                width: w_px,
                height: h_px,
            },
            presentOptions: D2D1_PRESENT_OPTIONS_NONE,
        };

        let rt = unsafe { self.d2d_factory.CreateHwndRenderTarget(&rt_props, &hwnd_props).ok()? };
        self.render_target = Some(rt.clone());
        Some(rt)
    }

    fn on_timer(&mut self, timer_id: usize) {
        if timer_id == TIMER_POLL_ID {
            self.refresh_state_from_backend();
            self.ui_ram_mb = crate::monitoring::read_self_ram_mb();
            self.request_redraw();
        } else if timer_id == TIMER_ANIM_ID {
            let target_cpu = self.state.metrics.cpu_usage_percent;
            let target_ram = self.state.metrics.ram_usage_percent;
            let target_gpu = self.state.metrics.gpu_usage_percent.unwrap_or(0.0);

            let diff = (target_cpu - self.anim_cpu).abs()
                + (target_ram - self.anim_ram).abs()
                + (target_gpu - self.anim_gpu).abs();

            let mut need_redraw = false;
            if diff > 0.15 {
                self.anim_cpu += (target_cpu - self.anim_cpu) * 0.22;
                self.anim_ram += (target_ram - self.anim_ram) * 0.22;
                self.anim_gpu += (target_gpu - self.anim_gpu) * 0.22;
                need_redraw = true;
            }
            if self.state.clean_scanning || self.state.clean_running || self.state.ping_running {
                self.anim_phase = (self.anim_phase + 0.03) % 1.0;
                need_redraw = true;
            }

            if self.screenshot_target.is_some() {
                self.screenshot_frames += 1;
                if self.screenshot_frames % 30 == 0 {
                    self.refresh_state_from_backend();
                }
                need_redraw = true;
                if self.screenshot_frames >= 120 && !self.screenshot_saved {
                    if let Some(target) = self.screenshot_target.clone() {
                        let _ = self.capture_screenshot_png(&target);
                    }
                    self.screenshot_saved = true;
                    unsafe {
                        let _ = KillTimer(self.hwnd, TIMER_ANIM_ID);
                        let _ = DestroyWindow(self.hwnd);
                    }
                    return;
                }
            }

            if need_redraw {
                self.request_redraw();
            }
        }
    }

    fn refresh_state_from_backend(&mut self) {
        let include_procs = self.active_tab == ActiveTab::ProcessesServices;
        if let Ok(IpcResponse::State { snapshot }) =
            self.transport.send(IpcRequest::GetState {
                include_processes: include_procs,
            })
        {
            if let Some((msg, is_err)) = snapshot.last_banner.clone() {
                self.banner = Some((
                    msg,
                    if is_err { ACCENT_CRIMSON } else { ACCENT_EMERALD },
                    Instant::now(),
                ));
            }
            self.state = *snapshot;
        }
    }

    fn send_and_notify(&mut self, req: IpcRequest) {
        match self.transport.send(req) {
            Ok(IpcResponse::Ok { message }) => {
                self.banner = Some((message, ACCENT_EMERALD, Instant::now()));
            }
            Ok(IpcResponse::Error { message }) => {
                self.banner = Some((message, ACCENT_CRIMSON, Instant::now()));
            }
            Err(e) => {
                self.banner = Some((e, ACCENT_CRIMSON, Instant::now()));
            }
            _ => {}
        }
        self.refresh_state_from_backend();
        self.request_redraw();
    }

    fn on_mouse_move(&mut self, x_px: f32, y_px: f32) {
        let x = x_px / self.dpi_scale;
        let y = y_px / self.dpi_scale;
        let hit = self
            .hit_regions
            .iter()
            .rev()
            .find(|h| x >= h.rect.left && x <= h.rect.right && y >= h.rect.top && y <= h.rect.bottom)
            .map(|h| h.id);

        unsafe {
            let cursor = if hit.is_some() { IDC_HAND } else { IDC_ARROW };
            if let Ok(hc) = LoadCursorW(None, cursor) {
                SetCursor(hc);
            }
        }

        if hit != self.hovered_id {
            self.hovered_id = hit;
            self.request_redraw();
        }
    }

    fn on_scroll(&mut self, wheel_delta: f32) {
        self.scroll_y = (self.scroll_y - wheel_delta * 0.45).clamp(0.0, self.max_scroll_y);
        self.request_redraw();
    }

    fn on_char(&mut self, c: char) {
        if self.focused_input == FocusedInput::None || c.is_control() {
            return;
        }
        let target = match self.focused_input {
            FocusedInput::CustomPingHost => &mut self.ping_host_input,
            FocusedInput::NewWhitelistExe => &mut self.new_whitelist_input,
            FocusedInput::NewGameExe => &mut self.new_game_input,
            FocusedInput::None => return,
        };
        if target.len() < 96 {
            target.push(c);
            self.request_redraw();
        }
    }

    fn on_key_down(&mut self, vk: u32) {
        if self.focused_input == FocusedInput::None {
            return;
        }
        match vk {
            0x08 => {
                // Backspace
                let target = match self.focused_input {
                    FocusedInput::CustomPingHost => &mut self.ping_host_input,
                    FocusedInput::NewWhitelistExe => &mut self.new_whitelist_input,
                    FocusedInput::NewGameExe => &mut self.new_game_input,
                    FocusedInput::None => return,
                };
                target.pop();
                self.request_redraw();
            }
            0x0D => {
                // Enter
                match self.focused_input {
                    FocusedInput::CustomPingHost => self.dispatch_action(UiAction::TriggerCustomPing),
                    FocusedInput::NewWhitelistExe => {
                        self.dispatch_action(UiAction::SubmitNewWhitelist)
                    }
                    FocusedInput::NewGameExe => self.dispatch_action(UiAction::SubmitNewGameExe),
                    FocusedInput::None => {}
                }
            }
            0x1B => {
                self.focused_input = FocusedInput::None;
                self.request_redraw();
            }
            _ => {}
        }
    }

    fn on_click(&mut self, x_px: f32, y_px: f32) {
        let x = x_px / self.dpi_scale;
        let y = y_px / self.dpi_scale;
        let action = self
            .hit_regions
            .iter()
            .rev()
            .find(|h| x >= h.rect.left && x <= h.rect.right && y >= h.rect.top && y <= h.rect.bottom)
            .map(|h| h.action.clone());

        if let Some(act) = action {
            if !matches!(act, UiAction::FocusField(_)) {
                self.focused_input = FocusedInput::None;
            }
            self.dispatch_action(act);
        } else if self.focused_input != FocusedInput::None {
            self.focused_input = FocusedInput::None;
            self.request_redraw();
        }
    }

    fn dispatch_action(&mut self, action: UiAction) {
        match action {
            UiAction::SwitchTab(tab) => {
                self.active_tab = tab;
                self.scroll_y = 0.0;
                if tab == ActiveTab::PcCleaner
                    && self.state.clean_categories.iter().all(|c| !c.scanned)
                {
                    let _ = self.transport.send(IpcRequest::ScanClean);
                }
                self.refresh_state_from_backend();
                self.request_redraw();
            }
            UiAction::SwitchProcSubTab(sub) => {
                self.proc_sub_tab = sub;
                self.scroll_y = 0.0;
                self.refresh_state_from_backend();
                self.request_redraw();
            }
            UiAction::ToggleBoost => self.send_and_notify(IpcRequest::ToggleBoost),
            UiAction::SelectProfile(p) => self.send_and_notify(IpcRequest::SetProfile { profile: p }),
            UiAction::ToggleAutoBoost => {
                let next = !self.state.config.auto_boost_enabled;
                self.send_and_notify(IpcRequest::SetAutoBoost { enabled: next });
            }
            UiAction::QuickCleanRam => self.send_and_notify(IpcRequest::QuickCleanRam),
            UiAction::OpenCleanerAndScan => {
                self.active_tab = ActiveTab::PcCleaner;
                self.scroll_y = 0.0;
                self.send_and_notify(IpcRequest::ScanClean);
            }
            UiAction::QuickPing(label, host) => {
                self.active_tab = ActiveTab::Monitoring;
                self.send_and_notify(IpcRequest::RunPing { label, host });
            }
            UiAction::RelaunchAdmin => {
                if let Some(ref mut g) = self.instance_guard {
                    g.release_now();
                }
                match win32_ops::relaunch_as_admin() {
                    Ok(()) => unsafe {
                        let _ = DestroyWindow(self.hwnd);
                    },
                    Err(e) => {
                        self.instance_guard = SingleInstanceGuard::try_acquire().ok().flatten();
                        self.banner = Some((e, ACCENT_CRIMSON, Instant::now()));
                        self.request_redraw();
                    }
                }
            }
            UiAction::BrowseAndAddGameExe => {
                if let Some(exe_name) = pick_exe_filename(self.hwnd) {
                    let display = exe_name
                        .strip_suffix(".exe")
                        .or_else(|| exe_name.strip_suffix(".EXE"))
                        .unwrap_or(&exe_name)
                        .to_string();
                    self.send_and_notify(IpcRequest::AddGame {
                        name: display,
                        exe_name,
                        profile: ProfileId::Competitive,
                    });
                }
            }
            UiAction::SubmitNewGameExe => {
                let exe = self.new_game_input.trim().to_string();
                if !exe.is_empty() {
                    let display = exe
                        .strip_suffix(".exe")
                        .or_else(|| exe.strip_suffix(".EXE"))
                        .unwrap_or(&exe)
                        .to_string();
                    self.new_game_input.clear();
                    self.send_and_notify(IpcRequest::AddGame {
                        name: display,
                        exe_name: exe,
                        profile: ProfileId::Competitive,
                    });
                }
            }
            UiAction::ToggleGameAuto(exe, enabled) => {
                self.send_and_notify(IpcRequest::ToggleGameAuto {
                    exe_name: exe,
                    enabled,
                });
            }
            UiAction::CycleGameProfile(exe) => {
                self.send_and_notify(IpcRequest::CycleGameProfile { exe_name: exe });
            }
            UiAction::ToggleGameAvoidCore0(exe) => {
                self.send_and_notify(IpcRequest::ToggleGameAvoidCore0 { exe_name: exe });
            }
            UiAction::RemoveGame(exe) => {
                self.send_and_notify(IpcRequest::RemoveGame { exe_name: exe });
            }
            UiAction::CycleProcRule(exe) => {
                self.send_and_notify(IpcRequest::CycleProcessRuleAction { exe_name: exe });
            }
            UiAction::ToggleServicePause(svc, enabled) => {
                self.send_and_notify(IpcRequest::ToggleServicePause {
                    service_name: svc,
                    enabled,
                });
            }
            UiAction::AddWhitelist(exe) => {
                self.send_and_notify(IpcRequest::AddUserWhitelist { exe_name: exe });
            }
            UiAction::RemoveWhitelist(exe) => {
                self.send_and_notify(IpcRequest::RemoveUserWhitelist { exe_name: exe });
            }
            UiAction::SubmitNewWhitelist => {
                let exe = self.new_whitelist_input.trim().to_string();
                if !exe.is_empty() {
                    self.new_whitelist_input.clear();
                    self.send_and_notify(IpcRequest::AddUserWhitelist { exe_name: exe });
                }
            }
            UiAction::ToggleCleanCat(id) => {
                self.send_and_notify(IpcRequest::ToggleCleanCategory { id });
            }
            UiAction::ScanClean => self.send_and_notify(IpcRequest::ScanClean),
            UiAction::ExecuteClean => {
                let cats: Vec<CleanCategoryId> = self
                    .state
                    .clean_categories
                    .iter()
                    .filter(|c| c.selected)
                    .map(|c| c.id)
                    .collect();
                self.send_and_notify(IpcRequest::RunClean { categories: cats });
            }
            UiAction::FocusField(f) => {
                self.focused_input = f;
                self.request_redraw();
            }
            UiAction::TriggerCustomPing => {
                let host = self.ping_host_input.trim().to_string();
                if !host.is_empty() {
                    self.send_and_notify(IpcRequest::RunPing {
                        label: format!("Serveur ({})", host),
                        host,
                    });
                }
            }
            UiAction::ToggleSettingLaunchWindows => {
                let c = &self.state.config;
                self.send_and_notify(IpcRequest::UpdateSettings {
                    launch_with_windows: !c.launch_with_windows,
                    start_minimized_to_tray: c.start_minimized_to_tray,
                    minimize_to_tray_on_close: c.minimize_to_tray_on_close,
                    toast_notifications: c.toast_notifications_enabled,
                    auto_crash_recovery: c.auto_crash_recovery,
                    standby_threshold_mb: c.standby_purge_threshold_mb,
                });
            }
            UiAction::ToggleSettingStartMin => {
                let c = &self.state.config;
                self.send_and_notify(IpcRequest::UpdateSettings {
                    launch_with_windows: c.launch_with_windows,
                    start_minimized_to_tray: !c.start_minimized_to_tray,
                    minimize_to_tray_on_close: c.minimize_to_tray_on_close,
                    toast_notifications: c.toast_notifications_enabled,
                    auto_crash_recovery: c.auto_crash_recovery,
                    standby_threshold_mb: c.standby_purge_threshold_mb,
                });
            }
            UiAction::ToggleSettingAutoCrash => {
                let c = &self.state.config;
                self.send_and_notify(IpcRequest::UpdateSettings {
                    launch_with_windows: c.launch_with_windows,
                    start_minimized_to_tray: c.start_minimized_to_tray,
                    minimize_to_tray_on_close: c.minimize_to_tray_on_close,
                    toast_notifications: c.toast_notifications_enabled,
                    auto_crash_recovery: !c.auto_crash_recovery,
                    standby_threshold_mb: c.standby_purge_threshold_mb,
                });
            }
            UiAction::SaveSnapshot => self.send_and_notify(IpcRequest::SaveManualSnapshot),
            UiAction::RestoreInitial => self.send_and_notify(IpcRequest::RestoreInitialState),
            UiAction::ExecuteCrashRecovery => {
                self.send_and_notify(IpcRequest::ExecutePendingCrashRecovery);
            }
            UiAction::SetLogFilter(f) => {
                self.log_filter = f;
                self.request_redraw();
            }
            UiAction::ClearLogs => self.send_and_notify(IpcRequest::ClearLogs),
            UiAction::DismissBanner => {
                self.banner = None;
                self.request_redraw();
            }
        }
    }

    fn paint_window(&mut self) {
        let Some(hwnd_rt) = self.ensure_render_target() else {
            return;
        };
        let Ok(rt) = hwnd_rt.cast::<ID2D1RenderTarget>() else {
            return;
        };

        unsafe {
            rt.BeginDraw();
        }
        self.render_scene(&rt, self.width_dip, self.height_dip);
        let hr = unsafe { rt.EndDraw(None, None) };
        if hr.is_err() {
            // Perte de surface (ex. verrouillage session) : recréation propre au prochain WM_PAINT
            self.render_target = None;
        }

        // Réduit le Working Set dès le premier rendu afin de rester largement sous 20 Mo RAM
        if !self.trimmed_once {
            self.trimmed_once = true;
            win32_ops::trim_self_working_set();
        }
        self.ui_ram_mb = crate::monitoring::read_self_ram_mb();
    }

    /// Capture pixel-parfaite de l'interface Direct2D via `ID2D1DCRenderTarget` + DIB 32-bit
    /// (totalement fiable même lorsque la fenêtre est derrière d'autres fenêtres en mode `--screenshot`).
    fn capture_screenshot_png(&mut self, output_path: &Path) -> Result<(), String> {
        let width_px = (self.width_dip * self.dpi_scale).round().max(640.0) as i32;
        let height_px = (self.height_dip * self.dpi_scale).round().max(480.0) as i32;

        unsafe {
            let mem_dc = CreateCompatibleDC(None);
            if mem_dc.is_invalid() {
                return Err("CreateCompatibleDC échec".to_string());
            }

            let bmi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width_px,
                    biHeight: -height_px, // Top-down DIB
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };

            let mut bits_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            let hbm = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0)
                .map_err(|e| format!("CreateDIBSection: {}", e))?;
            let old_obj = SelectObject(mem_dc, hbm);

            let dpi = self.dpi_scale * 96.0;
            let dc_props = D2D1_RENDER_TARGET_PROPERTIES {
                r#type: D2D1_RENDER_TARGET_TYPE_SOFTWARE,
                pixelFormat: D2D1_PIXEL_FORMAT {
                    format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    alphaMode: D2D1_ALPHA_MODE_PREMULTIPLIED,
                },
                dpiX: dpi,
                dpiY: dpi,
                ..Default::default()
            };

            let dc_rt: ID2D1DCRenderTarget = self
                .d2d_factory
                .CreateDCRenderTarget(&dc_props)
                .map_err(|e| format!("CreateDCRenderTarget: {}", e))?;
            let bind_rc = RECT {
                left: 0,
                top: 0,
                right: width_px,
                bottom: height_px,
            };
            dc_rt
                .BindDC(mem_dc, &bind_rc)
                .map_err(|e| format!("BindDC: {}", e))?;

            let rt: ID2D1RenderTarget = dc_rt.cast().map_err(|e| e.to_string())?;
            rt.BeginDraw();
            self.render_scene(&rt, width_px as f32 / self.dpi_scale, height_px as f32 / self.dpi_scale);
            let _ = rt.EndDraw(None, None);

            // Conversion BGRA -> RGBA pour PNG
            let pixel_count = (width_px as usize) * (height_px as usize);
            let src = std::slice::from_raw_parts(bits_ptr as *const u8, pixel_count * 4);
            let mut rgba_bytes = vec![0u8; pixel_count * 4];
            for i in 0..pixel_count {
                rgba_bytes[i * 4] = src[i * 4 + 2];
                rgba_bytes[i * 4 + 1] = src[i * 4 + 1];
                rgba_bytes[i * 4 + 2] = src[i * 4];
                rgba_bytes[i * 4 + 3] = 255;
            }

            SelectObject(mem_dc, old_obj);
            let _ = DeleteObject(hbm);
            let _ = DeleteDC(mem_dc);

            if let Some(parent) = output_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            if let Some(img) =
                image::RgbaImage::from_raw(width_px as u32, height_px as u32, rgba_bytes)
            {
                img.save(output_path).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RENDU COMPLET DIRECT2D / DIRECTWRITE
    // ═══════════════════════════════════════════════════════════════════════
    fn register_hit(&mut self, rect: D2D_RECT_F, action: UiAction) -> bool {
        let id = self.next_hit_id;
        self.next_hit_id += 1;
        let hovered = self.hovered_id == Some(id);
        self.hit_regions.push(HitRegion { id, rect, action });
        hovered
    }

    fn render_scene(&mut self, rt: &ID2D1RenderTarget, w: f32, h: f32) {
        self.hit_regions.clear();
        self.next_hit_id = 1;

        unsafe {
            rt.SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
            rt.Clear(Some(&BG_OLED));
        }

        let header_h = 58.0;
        let sidebar_w = 224.0;

        // Halo atmosphérique discret Craft.ro en haut du canvas
        if let Some(halo_indigo) = solid_brush(rt, with_alpha(ACCENT_INDIGO, 0.045)) {
            unsafe {
                rt.FillEllipse(
                    &D2D1_ELLIPSE {
                        point: pt(sidebar_w + (w - sidebar_w) * 0.5, header_h - 40.0),
                        radiusX: 340.0,
                        radiusY: 130.0,
                    },
                    &halo_indigo,
                );
            }
        }
        if let Some(halo_sky) = solid_brush(rt, with_alpha(ACCENT_CYAN, 0.025)) {
            unsafe {
                rt.FillEllipse(
                    &D2D1_ELLIPSE {
                        point: pt(w * 0.88, header_h - 20.0),
                        radiusX: 240.0,
                        radiusY: 110.0,
                    },
                    &halo_sky,
                );
            }
        }

        // 1. Barre supérieure
        self.draw_top_header(rt, w, header_h);

        // 2. Barre latérale de navigation
        self.draw_sidebar(rt, sidebar_w, header_h, h - header_h);

        // 3. Zone centrale (clippée pour scroll fluide)
        let content_rect = rect(sidebar_w, header_h, w, h);
        unsafe {
            rt.PushAxisAlignedClip(&content_rect, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        }

        let pad = 20.0;
        let cx = sidebar_w + pad;
        let cw = (w - sidebar_w - pad * 2.0).max(400.0);
        let mut cy = header_h + pad - self.scroll_y;

        // Bannière Crash-Recovery si présente
        if let Some(summary) = self.state.pending_crash_summary.clone() {
            let b_rc = rect(cx, cy, cx + cw, cy + 56.0);
            fill_rounded_card(rt, b_rc, 10.0, rgba(42, 24, 12, 1.0), ACCENT_AMBER);
            draw_text(
                rt,
                "CRASH-RECOVERY DÉTECTÉ — État système précédent non restauré",
                &self.typo.body_bold,
                rect(cx + 14.0, cy + 8.0, cx + cw - 190.0, cy + 28.0),
                ACCENT_AMBER,
            );
            draw_text(
                rt,
                &summary,
                &self.typo.small,
                rect(cx + 14.0, cy + 30.0, cx + cw - 190.0, cy + 50.0),
                TEXT_PRIMARY,
            );
            let btn_rc = rect(cx + cw - 174.0, cy + 12.0, cx + cw - 12.0, cy + 44.0);
            let hov = self.register_hit(btn_rc, UiAction::ExecuteCrashRecovery);
            draw_button(
                rt,
                btn_rc,
                "Restaurer",
                &self.typo.center_btn,
                ACCENT_AMBER,
                ACCENT_AMBER,
                TEXT_DARK,
                hov,
            );
            cy += 68.0;
        }

        // Bannière temporaire d'information
        if let Some((msg, col, since)) = self.banner.clone() {
            if since.elapsed() < Duration::from_secs(7) {
                let b_rc = rect(cx, cy, cx + cw, cy + 40.0);
                fill_rounded_card(rt, b_rc, 8.0, BG_CARD_ELEVATED, col);
                draw_glow_dot(rt, cx + 18.0, cy + 20.0, col, false);
                draw_text(
                    rt,
                    &msg,
                    &self.typo.body,
                    rect(cx + 32.0, cy + 11.0, cx + cw - 86.0, cy + 32.0),
                    TEXT_PRIMARY,
                );
                let close_rc = rect(cx + cw - 74.0, cy + 8.0, cx + cw - 10.0, cy + 32.0);
                let hov = self.register_hit(close_rc, UiAction::DismissBanner);
                draw_button(
                    rt,
                    close_rc,
                    "Fermer",
                    &self.typo.center_btn,
                    BG_CARD,
                    BORDER_BRIGHT,
                    TEXT_SECONDARY,
                    hov,
                );
                cy += 52.0;
            } else {
                self.banner = None;
            }
        }

        let end_y = match self.active_tab {
            ActiveTab::Dashboard => self.draw_tab_dashboard(rt, cx, cy, cw),
            ActiveTab::GamesProfiles => self.draw_tab_games(rt, cx, cy, cw),
            ActiveTab::ProcessesServices => self.draw_tab_processes(rt, cx, cy, cw),
            ActiveTab::PcCleaner => self.draw_tab_cleaner(rt, cx, cy, cw),
            ActiveTab::Monitoring => self.draw_tab_monitoring(rt, cx, cy, cw),
            ActiveTab::SettingsLogs => self.draw_tab_settings(rt, cx, cy, cw),
        };

        let content_total_h = (end_y + self.scroll_y) - header_h + 24.0;
        self.max_scroll_y = (content_total_h - (h - header_h)).max(0.0);
        if self.scroll_y > self.max_scroll_y {
            self.scroll_y = self.max_scroll_y;
        }

        unsafe {
            rt.PopAxisAlignedClip();
        }
    }

    fn draw_top_header(&mut self, rt: &ID2D1RenderTarget, w: f32, h: f32) {
        let hdr = rect(0.0, 0.0, w, h);
        fill_rect(rt, hdr, BG_SIDEBAR);
        draw_line(rt, 0.0, h - 0.5, w, h - 0.5, BORDER_SUBTLE, 1.0);

        let boost_active = self.state.stats.active;
        let emblem_col = if boost_active {
            ACCENT_EMERALD
        } else {
            ACCENT_CYAN
        };
        let emblem_rc = rect(16.0, 14.0, 44.0, 42.0);
        fill_rounded_card(
            rt,
            emblem_rc,
            7.0,
            with_alpha(emblem_col, 0.14),
            emblem_col,
        );
        self.draw_nav_icon(
            rt,
            rect(21.0, 19.0, 39.0, 37.0),
            NavIcon::Bolt,
            emblem_col,
        );

        draw_text(
            rt,
            "WINBOOST",
            &self.typo.title_md,
            rect(54.0, 10.0, 175.0, 32.0),
            TEXT_PRIMARY,
        );
        draw_text(
            rt,
            "v1.0.0",
            &self.typo.eyebrow,
            rect(162.0, 13.0, 232.0, 31.0),
            ACCENT_EMERALD,
        );
        let sub = format!(
            "Optimiseur & nettoyeur Windows  •  {}",
            self.state.capabilities.os_label
        );
        draw_text(
            rt,
            &sub,
            &self.typo.small,
            rect(54.0, 32.0, 480.0, 50.0),
            TEXT_SECONDARY,
        );

        // Badges à droite
        let mut rx = w - 16.0;

        if self.state.capabilities.is_admin {
            let b = rect(rx - 106.0, 17.0, rx, 41.0);
            draw_luminous_badge(rt, b, "ADMIN ACTIF", &self.typo.eyebrow, ACCENT_EMERALD, false);
            rx -= 116.0;
        } else {
            let btn = rect(rx - 156.0, 16.0, rx, 42.0);
            let hov = self.register_hit(btn, UiAction::RelaunchAdmin);
            draw_button(
                rt,
                btn,
                "Relancer en Admin",
                &self.typo.center_btn,
                ACCENT_AMBER,
                ACCENT_AMBER,
                TEXT_DARK,
                hov,
            );
            rx -= 166.0;
            let b = rect(rx - 122.0, 17.0, rx, 41.0);
            draw_luminous_badge(rt, b, "MODE STANDARD", &self.typo.eyebrow, ACCENT_AMBER, false);
            rx -= 132.0;
        }

        let boost_badge = rect(rx - 124.0, 17.0, rx, 41.0);
        if boost_active {
            draw_luminous_badge(
                rt,
                boost_badge,
                "BOOST ACTIF",
                &self.typo.eyebrow,
                ACCENT_EMERALD,
                true,
            );
        } else {
            draw_luminous_badge(
                rt,
                boost_badge,
                "VEILLE TACTIQUE",
                &self.typo.eyebrow,
                ACCENT_CYAN,
                false,
            );
        }
        rx -= 136.0;

        let ram_txt = format!(
            "UI {:.1} Mo • Svc {:.1} Mo",
            self.ui_ram_mb, self.state.svc_ram_mb
        );
        draw_text(
            rt,
            &ram_txt,
            &self.typo.right_small,
            rect(rx - 190.0, 18.0, rx, 40.0),
            TEXT_SECONDARY,
        );
    }

    fn draw_sidebar(&mut self, rt: &ID2D1RenderTarget, w: f32, top: f32, h: f32) {
        fill_rect(rt, rect(0.0, top, w, top + h), BG_SIDEBAR);
        draw_line(rt, w - 0.5, top, w - 0.5, top + h, BORDER_SUBTLE, 1.0);

        let mut y = top + 16.0;
        draw_text(
            rt,
            "CONSOLE SYSTÈME",
            &self.typo.eyebrow,
            rect(16.0, y, w - 16.0, y + 18.0),
            TEXT_SECONDARY,
        );
        y += 26.0;

        let nav = [
            (ActiveTab::Dashboard, "Accueil / Statut", NavIcon::Bolt),
            (ActiveTab::GamesProfiles, "Jeux & Profils", NavIcon::Gamepad),
            (
                ActiveTab::ProcessesServices,
                "Processus & Services",
                NavIcon::Layers,
            ),
            (ActiveTab::PcCleaner, "Nettoyage PC", NavIcon::SparkClean),
            (ActiveTab::Monitoring, "Monitoring", NavIcon::Pulse),
            (
                ActiveTab::SettingsLogs,
                "Paramètres & Journaux",
                NavIcon::Settings,
            ),
        ];

        for (tab, label, icon) in nav {
            let item_rc = rect(12.0, y, w - 12.0, y + 38.0);
            let selected = self.active_tab == tab;
            let hovered = self.register_hit(item_rc, UiAction::SwitchTab(tab));

            if selected {
                fill_rounded_card(
                    rt,
                    item_rc,
                    8.0,
                    with_alpha(ACCENT_EMERALD, 0.11),
                    with_alpha(ACCENT_EMERALD, 0.7),
                );
                fill_rounded_rect(
                    rt,
                    rect(item_rc.left + 2.0, item_rc.top + 8.0, item_rc.left + 5.0, item_rc.bottom - 8.0),
                    2.0,
                    ACCENT_EMERALD,
                );
            } else if hovered {
                fill_rounded_card(rt, item_rc, 8.0, BG_CARD_ELEVATED, BORDER_BRIGHT);
            }

            let icon_col = if selected {
                ACCENT_EMERALD
            } else if hovered {
                ACCENT_CYAN
            } else {
                TEXT_SECONDARY
            };
            self.draw_nav_icon(
                rt,
                rect(item_rc.left + 14.0, item_rc.top + 11.0, item_rc.left + 30.0, item_rc.top + 27.0),
                icon,
                icon_col,
            );
            draw_text(
                rt,
                label,
                &self.typo.body_bold,
                rect(item_rc.left + 38.0, item_rc.top, item_rc.right - 8.0, item_rc.bottom),
                if selected { ACCENT_EMERALD } else { TEXT_PRIMARY },
            );
            y += 43.0;
        }

        // Carte Garde-fous en bas de la barre latérale
        y += 14.0;
        let card_rc = rect(12.0, y, w - 12.0, y + 162.0);
        fill_rounded_card(rt, card_rc, 10.0, BG_CARD, BORDER_SUBTLE);
        let mut gy = y + 12.0;
        draw_text(
            rt,
            "GARDE-FOUS ACTIFS",
            &self.typo.eyebrow,
            rect(24.0, gy, w - 24.0, gy + 16.0),
            TEXT_SECONDARY,
        );
        gy += 22.0;

        let auto_str = if self.state.config.auto_boost_enabled {
            "2.5 s"
        } else {
            "Manuel"
        };
        let prof_name = self.state.config.active_global_profile.display_name();
        let snap_str = if self.state.recovery_file_summary.is_some() {
            "Actif"
        } else {
            "Propre"
        };
        let rows = [
            ("Auto-Boost", auto_str, ACCENT_EMERALD),
            ("Profil", prof_name.as_str(), ACCENT_CYAN),
            (
                "Snapshot",
                snap_str,
                if self.state.recovery_file_summary.is_some() {
                    ACCENT_AMBER
                } else {
                    ACCENT_EMERALD
                },
            ),
            ("Anti-Cheat", "Verrouillé", ACCENT_EMERALD),
            ("IPC Pipe", "ACL Stricte", ACCENT_INDIGO),
            ("Rendu", "Direct2D 0 VRAM", ACCENT_EMERALD),
        ];
        for (k, v, c) in rows {
            draw_text(
                rt,
                k,
                &self.typo.small,
                rect(24.0, gy, w - 90.0, gy + 18.0),
                TEXT_SECONDARY,
            );
            draw_text(
                rt,
                v,
                &self.typo.right_small,
                rect(w - 125.0, gy - 1.0, w - 24.0, gy + 18.0),
                c,
            );
            gy += 20.0;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ONGLET 1 : ACCUEIL / STATUT
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_tab_dashboard(&mut self, rt: &ID2D1RenderTarget, x: f32, mut y: f32, w: f32) -> f32 {
        let boost_active = self.state.stats.active;

        // Carte Hero Boost ON/OFF
        let hero_rc = rect(x, y, x + w, y + 96.0);
        fill_rounded_card(
            rt,
            hero_rc,
            12.0,
            if boost_active {
                BG_CARD_ACTIVE_BOOST
            } else {
                BG_CARD
            },
            if boost_active {
                ACCENT_EMERALD
            } else {
                BORDER_BRIGHT
            },
        );
        draw_glow_dot(
            rt,
            x + 22.0,
            y + 22.0,
            if boost_active {
                ACCENT_EMERALD
            } else {
                ACCENT_CYAN
            },
            boost_active,
        );
        draw_text(
            rt,
            if boost_active {
                "SESSION OPTIMISÉE EN COURS • RÉVERSIBILITÉ 100 %"
            } else {
                "PRÊT POUR LE JEU • ARCHITECTURE DÉCOUPLÉE (0 MO EN JEU)"
            },
            &self.typo.eyebrow,
            rect(x + 34.0, y + 13.0, x + w - 230.0, y + 31.0),
            if boost_active {
                ACCENT_EMERALD
            } else {
                ACCENT_CYAN
            },
        );
        let hero_title = if boost_active {
            if let Some(ref game) = self.state.stats.detected_game_name {
                format!("BOOST ACTIF — {}", game)
            } else {
                "BOOST MANUEL ACTIF".to_string()
            }
        } else {
            "SYSTÈME EN VEILLE TACTIQUE".to_string()
        };
        draw_text(
            rt,
            &hero_title,
            &self.typo.title_lg,
            rect(x + 18.0, y + 34.0, x + w - 230.0, y + 64.0),
            TEXT_PRIMARY,
        );
        let hero_sub = format!(
            "Auto-Boost : {}  •  Plan : {}  •  {}",
            if self.state.config.auto_boost_enabled {
                "Actif (2.5s)"
            } else {
                "Manuel"
            },
            self.state.capabilities.active_power_plan_name,
            self.state.capabilities.gpu_name
        );
        draw_text(
            rt,
            &hero_sub,
            &self.typo.small,
            rect(x + 18.0, y + 66.0, x + w - 230.0, y + 86.0),
            TEXT_SECONDARY,
        );

        let boost_btn = rect(x + w - 216.0, y + 24.0, x + w - 18.0, y + 72.0);
        let hov = self.register_hit(boost_btn, UiAction::ToggleBoost);
        draw_button(
            rt,
            boost_btn,
            if boost_active {
                "COUPER LE BOOST"
            } else {
                "ACTIVER LE BOOST"
            },
            &self.typo.center_btn,
            if boost_active {
                ACCENT_CRIMSON
            } else {
                ACCENT_EMERALD
            },
            if boost_active {
                ACCENT_CRIMSON
            } else {
                ACCENT_EMERALD
            },
            if boost_active { TEXT_PRIMARY } else { TEXT_DARK },
            hov,
        );
        y += 112.0;

        // 4 Cartes KPI avec Jauges Circulaires Animées (CPU / RAM / GPU) + Bilan Session
        let gap = 12.0;
        let col_w = (w - gap * 3.0) / 4.0;
        let kpi_h = 110.0;

        self.draw_radial_kpi_card(
            rt,
            rect(x, y, x + col_w, y + kpi_h),
            "PROCESSEUR",
            self.anim_cpu,
            &format!("{:.0}%", self.anim_cpu),
            &format!("{} cœurs logiques", self.state.capabilities.logical_cpu_count),
            ACCENT_CYAN,
        );
        self.draw_radial_kpi_card(
            rt,
            rect(x + col_w + gap, y, x + col_w * 2.0 + gap, y + kpi_h),
            "MÉMOIRE RAM",
            self.anim_ram,
            &format!("{:.0}%", self.anim_ram),
            &format!(
                "{:.1} Go libres / {:.0} Go",
                self.state.metrics.ram_free_gb, self.state.metrics.ram_total_gb
            ),
            ACCENT_EMERALD,
        );
        let gpu_label = if self.state.metrics.gpu_usage_percent.is_some() {
            format!("{:.0}%", self.anim_gpu)
        } else {
            "WDDM".to_string()
        };
        let gpu_sub = self
            .state
            .metrics
            .gpu_temp_c
            .map(|t| format!("Temp : {:.0} °C", t))
            .unwrap_or_else(|| "DirectX / WDDM".to_string());
        self.draw_radial_kpi_card(
            rt,
            rect(
                x + (col_w + gap) * 2.0,
                y,
                x + col_w * 3.0 + gap * 2.0,
                y + kpi_h,
            ),
            "CARTE GPU",
            self.anim_gpu,
            &gpu_label,
            &gpu_sub,
            ACCENT_INDIGO,
        );

        // Carte Bilan Session
        let bx = x + (col_w + gap) * 3.0;
        let b_rc = rect(bx, y, x + w, y + kpi_h);
        fill_rounded_card(rt, b_rc, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(
            rt,
            "BILAN SESSION",
            &self.typo.eyebrow,
            rect(bx + 14.0, y + 10.0, b_rc.right - 12.0, y + 26.0),
            TEXT_SECONDARY,
        );
        let ram_freed = format!("{:.1} Mo", self.state.stats.ram_freed_mb);
        let susp_cnt = format!("{}", self.state.stats.suspended_processes_count);
        let svc_cnt = format!("{}", self.state.stats.paused_services_count);
        let qos_str = if self.state.stats.qos_policy_active {
            "DSCP 46"
        } else {
            "Standard"
        };
        let mut by = y + 30.0;
        for (k, v, c) in [
            ("RAM libérée", ram_freed.as_str(), ACCENT_EMERALD),
            ("Proc. suspendus", susp_cnt.as_str(), ACCENT_CYAN),
            ("Services pause", svc_cnt.as_str(), ACCENT_INDIGO),
            ("Priorité QoS", qos_str, ACCENT_AMBER),
        ] {
            draw_text(
                rt,
                k,
                &self.typo.small,
                rect(bx + 14.0, by, b_rc.right - 70.0, by + 18.0),
                TEXT_SECONDARY,
            );
            draw_text(
                rt,
                v,
                &self.typo.right_small,
                rect(bx + 80.0, by - 1.0, b_rc.right - 14.0, by + 18.0),
                c,
            );
            by += 18.5;
        }

        y += kpi_h + 18.0;

        // Profils Globaux (3 cartes)
        draw_text(
            rt,
            "PROFILS D'OPTIMISATION GLOBAUX",
            &self.typo.eyebrow,
            rect(x, y, x + w, y + 18.0),
            TEXT_SECONDARY,
        );
        y += 22.0;

        let p_col_w = (w - gap * 2.0) / 3.0;
        let p_h = 166.0;
        let profiles = self.state.config.profiles.clone();
        let active_id = self.state.config.active_global_profile.clone();

        for (i, prof) in profiles.iter().take(3).enumerate() {
            let px = x + (p_col_w + gap) * i as f32;
            let prc = rect(px, y, px + p_col_w, y + p_h);
            let selected = prof.id == active_id;
            fill_rounded_card(
                rt,
                prc,
                10.0,
                if selected { BG_CARD_ELEVATED } else { BG_CARD },
                if selected {
                    ACCENT_EMERALD
                } else {
                    BORDER_SUBTLE
                },
            );
            draw_text(
                rt,
                &prof.id.display_name(),
                &self.typo.heading,
                rect(px + 14.0, y + 10.0, prc.right - 74.0, y + 30.0),
                if selected {
                    ACCENT_EMERALD
                } else {
                    TEXT_PRIMARY
                },
            );
            if selected {
                draw_luminous_badge(
                    rt,
                    rect(prc.right - 72.0, y + 10.0, prc.right - 12.0, y + 32.0),
                    "ACTIF",
                    &self.typo.eyebrow,
                    ACCENT_EMERALD,
                    true,
                );
            }
            draw_text(
                rt,
                &prof.description,
                &self.typo.small,
                rect(px + 14.0, y + 36.0, prc.right - 14.0, y + 100.0),
                TEXT_SECONDARY,
            );
            let power_short = match prof.power_plan {
                crate::models::PowerPlanTarget::KeepCurrent => "Actuel",
                crate::models::PowerPlanTarget::Balanced => "Équilibré",
                crate::models::PowerPlanTarget::HighPerformance => "Hautes Perf.",
                crate::models::PowerPlanTarget::UltimatePerformance => "Ultimate",
            };
            let cpu_short = match prof.game_cpu_priority {
                crate::models::SafeCpuPriority::Normal => "Normale",
                crate::models::SafeCpuPriority::AboveNormal => "Supérieure",
                crate::models::SafeCpuPriority::High => "Haute (High)",
            };
            let meta = format!("Alim : {}  •  CPU : {}", power_short, cpu_short);
            draw_text(
                rt,
                &meta,
                &self.typo.small,
                rect(px + 14.0, y + 104.0, prc.right - 14.0, y + 124.0),
                TEXT_PRIMARY,
            );
            if !selected {
                let sbtn = rect(px + 14.0, y + 128.0, prc.right - 14.0, y + 154.0);
                let hov = self.register_hit(sbtn, UiAction::SelectProfile(prof.id.clone()));
                draw_button(
                    rt,
                    sbtn,
                    "Sélectionner ce profil",
                    &self.typo.center_btn,
                    BG_CARD_ELEVATED,
                    BORDER_BRIGHT,
                    TEXT_PRIMARY,
                    hov,
                );
            }
        }
        y += p_h + 14.0;

        // Ligne inférieure : État Windows Gaming + Commandes rapides
        let half_w = (w - gap) / 2.0;
        let bot_h = 148.0;

        let left_rc = rect(x, y, x + half_w, y + bot_h);
        fill_rounded_card(rt, left_rc, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(
            rt,
            "ÉTAT SYSTÈME WINDOWS GAMING",
            &self.typo.eyebrow,
            rect(x + 14.0, y + 12.0, left_rc.right - 14.0, y + 28.0),
            TEXT_SECONDARY,
        );
        let gm = match self.state.capabilities.game_mode_enabled {
            Some(true) => ("Activé", ACCENT_EMERALD),
            Some(false) => ("Désactivé (auto en jeu)", ACCENT_AMBER),
            None => ("Par défaut Windows", ACCENT_CYAN),
        };
        let hags = match self.state.capabilities.hags_enabled {
            Some(true) => ("Activée (HwSchMode=2)", ACCENT_EMERALD),
            Some(false) => ("Désactivée", ACCENT_AMBER),
            None => ("Pilote / WDDM", TEXT_SECONDARY),
        };
        let mut sy = y + 38.0;
        for (k, (v, c)) in [
            ("Mode Jeu Windows (Game Mode)", gm),
            ("Planification GPU matérielle (HAGS)", hags),
            (
                "Plan d'alimentation actif (powrprof)",
                (
                    self.state.capabilities.active_power_plan_name.as_str(),
                    ACCENT_CYAN,
                ),
            ),
            (
                "Whitelist Noyau & Anti-Cheat",
                ("Vanguard, EAC, BattlEye, Ricochet", ACCENT_EMERALD),
            ),
        ] {
            draw_text(
                rt,
                k,
                &self.typo.body,
                rect(x + 14.0, sy, left_rc.right - 160.0, sy + 20.0),
                TEXT_PRIMARY,
            );
            draw_text(
                rt,
                v,
                &self.typo.right_body,
                rect(x + 160.0, sy - 2.0, left_rc.right - 14.0, sy + 20.0),
                c,
            );
            sy += 26.0;
        }

        let rx = x + half_w + gap;
        let right_rc = rect(rx, y, x + w, y + bot_h);
        fill_rounded_card(rt, right_rc, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(
            rt,
            "COMMANDES RAPIDES",
            &self.typo.eyebrow,
            rect(rx + 14.0, y + 12.0, right_rc.right - 14.0, y + 28.0),
            TEXT_SECONDARY,
        );

        let chk_rc = rect(rx + 14.0, y + 40.0, right_rc.right - 14.0, y + 66.0);
        let chk_hov = self.register_hit(chk_rc, UiAction::ToggleAutoBoost);
        draw_checkbox(
            rt,
            rx + 14.0,
            y + 44.0,
            self.state.config.auto_boost_enabled,
            chk_hov,
        );
        draw_text(
            rt,
            "Auto-Boost : détecter mes jeux automatiquement (scan 2.5s)",
            &self.typo.body,
            rect(rx + 40.0, y + 43.0, right_rc.right - 14.0, y + 66.0),
            TEXT_PRIMARY,
        );

        let qbtn_w = (half_w - 44.0) / 3.0;
        let qy = y + 84.0;
        let q1 = rect(rx + 14.0, qy, rx + 14.0 + qbtn_w, qy + 38.0);
        let h1 = self.register_hit(q1, UiAction::QuickCleanRam);
        draw_button(
            rt,
            q1,
            "Nettoyer RAM",
            &self.typo.center_btn,
            BG_CARD_ELEVATED,
            ACCENT_CYAN,
            TEXT_PRIMARY,
            h1,
        );

        let q2 = rect(q1.right + 8.0, qy, q1.right + 8.0 + qbtn_w, qy + 38.0);
        let h2 = self.register_hit(q2, UiAction::OpenCleanerAndScan);
        draw_button(
            rt,
            q2,
            "Nettoyage PC",
            &self.typo.center_btn,
            BG_CARD_ELEVATED,
            ACCENT_INDIGO,
            TEXT_PRIMARY,
            h2,
        );

        let q3 = rect(q2.right + 8.0, qy, right_rc.right - 14.0, qy + 38.0);
        let h3 = self.register_hit(
            q3,
            UiAction::QuickPing("Cloudflare DNS".to_string(), "1.1.1.1".to_string()),
        );
        draw_button(
            rt,
            q3,
            "Ping 1.1.1.1",
            &self.typo.center_btn,
            BG_CARD_ELEVATED,
            ACCENT_EMERALD,
            TEXT_PRIMARY,
            h3,
        );

        y + bot_h + 12.0
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ONGLET 2 : JEUX & PROFILS
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_tab_games(&mut self, rt: &ID2D1RenderTarget, x: f32, mut y: f32, w: f32) -> f32 {
        draw_text(
            rt,
            "JEUX & PROFILS PAR APPLICATION",
            &self.typo.title_md,
            rect(x, y, x + w, y + 24.0),
            TEXT_PRIMARY,
        );
        draw_text(
            rt,
            "Cliquez sur le profil ou les options de chaque jeu pour les personnaliser. Ajoutez n'importe quel .exe.",
            &self.typo.small,
            rect(x, y + 25.0, x + w, y + 43.0),
            TEXT_SECONDARY,
        );
        y += 50.0;

        // Barre d'ajout de jeu
        let add_rc = rect(x, y, x + w, y + 58.0);
        fill_rounded_card(rt, add_rc, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(
            rt,
            "Ajouter un jeu (.exe) :",
            &self.typo.body_bold,
            rect(x + 14.0, y + 14.0, x + 170.0, y + 44.0),
            TEXT_PRIMARY,
        );
        let field_rc = rect(x + 174.0, y + 14.0, x + w - 310.0, y + 44.0);
        let f_hov = self.register_hit(field_rc, UiAction::FocusField(FocusedInput::NewGameExe));
        draw_text_input(
            rt,
            field_rc,
            &self.new_game_input,
            "ex: valorant.exe",
            self.focused_input == FocusedInput::NewGameExe,
            f_hov,
            &self.typo.mono,
        );
        let add_btn = rect(x + w - 298.0, y + 14.0, x + w - 168.0, y + 44.0);
        let ah = self.register_hit(add_btn, UiAction::SubmitNewGameExe);
        draw_button(
            rt,
            add_btn,
            "+ Ajouter",
            &self.typo.center_btn,
            ACCENT_EMERALD,
            ACCENT_EMERALD,
            TEXT_DARK,
            ah,
        );
        let browse_btn = rect(x + w - 156.0, y + 14.0, x + w - 14.0, y + 44.0);
        let bh = self.register_hit(browse_btn, UiAction::BrowseAndAddGameExe);
        draw_button(
            rt,
            browse_btn,
            "Parcourir .exe...",
            &self.typo.center_btn,
            BG_CARD_ELEVATED,
            ACCENT_CYAN,
            TEXT_PRIMARY,
            bh,
        );
        y += 72.0;

        // Tableau des jeux
        let games = self.state.config.games.clone();
        let row_h = 34.0;
        let table_h = 38.0 + games.len() as f32 * row_h + 12.0;
        fill_rounded_card(rt, rect(x, y, x + w, y + table_h), 10.0, BG_CARD, BORDER_SUBTLE);

        draw_text(rt, "AUTO", &self.typo.eyebrow, rect(x + 14.0, y + 10.0, x + 64.0, y + 30.0), TEXT_SECONDARY);
        draw_text(rt, "JEU", &self.typo.eyebrow, rect(x + 70.0, y + 10.0, x + 280.0, y + 30.0), TEXT_SECONDARY);
        draw_text(rt, "EXÉCUTABLE", &self.typo.eyebrow, rect(x + 286.0, y + 10.0, x + 520.0, y + 30.0), TEXT_SECONDARY);
        draw_text(rt, "PROFIL (CLIC)", &self.typo.eyebrow, rect(x + 526.0, y + 10.0, x + 710.0, y + 30.0), TEXT_SECONDARY);
        draw_text(rt, "CORE 0", &self.typo.eyebrow, rect(x + 716.0, y + 10.0, x + 810.0, y + 30.0), TEXT_SECONDARY);
        draw_line(rt, x + 12.0, y + 34.0, x + w - 12.0, y + 34.0, BORDER_SUBTLE, 1.0);

        let mut ry = y + 38.0;
        for (idx, g) in games.iter().enumerate() {
            if idx % 2 == 1 {
                fill_rect(rt, rect(x + 6.0, ry, x + w - 6.0, ry + row_h), rgba(22, 30, 46, 0.55));
            }
            let c_rc = rect(x + 16.0, ry + 7.0, x + 36.0, ry + 27.0);
            let ch = self.register_hit(
                c_rc,
                UiAction::ToggleGameAuto(g.exe_name.clone(), !g.auto_boost_enabled),
            );
            draw_checkbox(rt, x + 16.0, ry + 8.0, g.auto_boost_enabled, ch);

            draw_text(rt, &g.name, &self.typo.body_bold, rect(x + 70.0, ry, x + 280.0, ry + row_h), TEXT_PRIMARY);
            draw_text(rt, &g.exe_name, &self.typo.mono, rect(x + 286.0, ry, x + 520.0, ry + row_h), TEXT_SECONDARY);

            let p_btn = rect(x + 526.0, ry + 4.0, x + 696.0, ry + row_h - 4.0);
            let ph = self.register_hit(p_btn, UiAction::CycleGameProfile(g.exe_name.clone()));
            let p_col = match g.assigned_profile {
                ProfileId::Competitive => ACCENT_EMERALD,
                ProfileId::SilentLaptop => ACCENT_INDIGO,
                _ => ACCENT_CYAN,
            };
            draw_button(
                rt,
                p_btn,
                &g.assigned_profile.display_name(),
                &self.typo.center_btn,
                BG_CARD_ELEVATED,
                p_col,
                p_col,
                ph,
            );

            let avoid = g.override_avoid_core_0.unwrap_or(false);
            let c0_btn = rect(x + 716.0, ry + 4.0, x + 806.0, ry + row_h - 4.0);
            let c0h = self.register_hit(c0_btn, UiAction::ToggleGameAvoidCore0(g.exe_name.clone()));
            draw_button(
                rt,
                c0_btn,
                if avoid { "Exclu" } else { "Auto" },
                &self.typo.center_btn,
                BG_CARD_ELEVATED,
                if avoid { ACCENT_EMERALD } else { BORDER_SUBTLE },
                if avoid { ACCENT_EMERALD } else { TEXT_SECONDARY },
                c0h,
            );

            if g.is_custom {
                let rm_btn = rect(x + w - 92.0, ry + 4.0, x + w - 14.0, ry + row_h - 4.0);
                let rmh = self.register_hit(rm_btn, UiAction::RemoveGame(g.exe_name.clone()));
                draw_button(
                    rt,
                    rm_btn,
                    "Suppr.",
                    &self.typo.center_btn,
                    BG_CARD_ELEVATED,
                    ACCENT_CRIMSON,
                    ACCENT_CRIMSON,
                    rmh,
                );
            }
            ry += row_h;
        }
        y + table_h + 12.0
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ONGLET 3 : PROCESSUS & SERVICES
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_tab_processes(&mut self, rt: &ID2D1RenderTarget, x: f32, mut y: f32, w: f32) -> f32 {
        draw_text(
            rt,
            "PROCESSUS, SERVICES & LISTE BLANCHE INVIOLABLE",
            &self.typo.title_md,
            rect(x, y, x + w, y + 24.0),
            TEXT_PRIMARY,
        );
        y += 32.0;

        // Sous-onglets
        let subs = [
            (ProcSubTab::ManagedRules, "Règles arrière-plan"),
            (ProcSubTab::WindowsServices, "Services Windows"),
            (ProcSubTab::RunningProcesses, "Processus actifs"),
            (ProcSubTab::Whitelist, "Whitelist inviolable & perso"),
        ];
        let mut sx = x;
        for (st, label) in subs {
            let bw = 185.0;
            let brc = rect(sx, y, sx + bw, y + 32.0);
            let sel = self.proc_sub_tab == st;
            let hov = self.register_hit(brc, UiAction::SwitchProcSubTab(st));
            draw_button(
                rt,
                brc,
                label,
                &self.typo.center_btn,
                if sel { BG_CARD_ELEVATED } else { BG_CARD },
                if sel { ACCENT_EMERALD } else { BORDER_SUBTLE },
                if sel { ACCENT_EMERALD } else { TEXT_PRIMARY },
                hov,
            );
            sx += bw + 8.0;
        }
        y += 44.0;

        match self.proc_sub_tab {
            ProcSubTab::ManagedRules => {
                let rules = self.state.config.process_rules.clone();
                let row_h = 34.0;
                let h = 42.0 + rules.len() as f32 * row_h;
                fill_rounded_card(rt, rect(x, y, x + w, y + h), 10.0, BG_CARD, BORDER_SUBTLE);
                draw_text(rt, "PROCESSUS", &self.typo.eyebrow, rect(x + 14.0, y + 10.0, x + 280.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "CATÉGORIE", &self.typo.eyebrow, rect(x + 290.0, y + 10.0, x + 520.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "ACTION EN JEU (CLIQUER POUR CHANGER)", &self.typo.eyebrow, rect(x + 530.0, y + 10.0, x + w - 14.0, y + 30.0), TEXT_SECONDARY);
                draw_line(rt, x + 12.0, y + 34.0, x + w - 12.0, y + 34.0, BORDER_SUBTLE, 1.0);

                let mut ry = y + 38.0;
                for (i, r) in rules.iter().enumerate() {
                    if i % 2 == 1 {
                        fill_rect(rt, rect(x + 6.0, ry, x + w - 6.0, ry + row_h), rgba(22, 30, 46, 0.5));
                    }
                    draw_text(rt, &r.exe_name, &self.typo.mono, rect(x + 14.0, ry, x + 280.0, ry + row_h), TEXT_PRIMARY);
                    draw_text(rt, &r.category, &self.typo.body, rect(x + 290.0, ry + 7.0, x + 520.0, ry + row_h), TEXT_SECONDARY);

                    let abtn = rect(x + 530.0, ry + 4.0, x + 730.0, ry + row_h - 4.0);
                    let ah = self.register_hit(abtn, UiAction::CycleProcRule(r.exe_name.clone()));
                    let acol = match r.action {
                        ProcessAction::Suspend => ACCENT_EMERALD,
                        ProcessAction::CloseGracefully => ACCENT_AMBER,
                        ProcessAction::Ignore => TEXT_SECONDARY,
                    };
                    draw_button(
                        rt,
                        abtn,
                        r.action.label(),
                        &self.typo.center_btn,
                        BG_CARD_ELEVATED,
                        acol,
                        acol,
                        ah,
                    );
                    ry += row_h;
                }
                y + h + 12.0
            }
            ProcSubTab::WindowsServices => {
                let svcs = self.state.config.service_rules.clone();
                let states = self.state.service_states.clone();
                let row_h = 46.0;
                let h = 42.0 + svcs.len() as f32 * row_h;
                fill_rounded_card(rt, rect(x, y, x + w, y + h), 10.0, BG_CARD, BORDER_SUBTLE);
                draw_text(rt, "PAUSE", &self.typo.eyebrow, rect(x + 14.0, y + 10.0, x + 70.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "SERVICE WINDOWS", &self.typo.eyebrow, rect(x + 76.0, y + 10.0, x + 360.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "ÉTAT", &self.typo.eyebrow, rect(x + 366.0, y + 10.0, x + 480.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "DESCRIPTION", &self.typo.eyebrow, rect(x + 486.0, y + 10.0, x + w - 14.0, y + 30.0), TEXT_SECONDARY);
                draw_line(rt, x + 12.0, y + 34.0, x + w - 12.0, y + 34.0, BORDER_SUBTLE, 1.0);

                let mut ry = y + 38.0;
                for s in &svcs {
                    let crc = rect(x + 18.0, ry + 12.0, x + 38.0, ry + 32.0);
                    let ch = self.register_hit(
                        crc,
                        UiAction::ToggleServicePause(s.service_name.clone(), !s.enabled_for_pause),
                    );
                    draw_checkbox(rt, x + 18.0, ry + 13.0, s.enabled_for_pause, ch);
                    draw_text(rt, &s.display_name, &self.typo.body_bold, rect(x + 76.0, ry + 4.0, x + 360.0, ry + 24.0), TEXT_PRIMARY);
                    draw_text(rt, &s.service_name, &self.typo.mono, rect(x + 76.0, ry + 24.0, x + 360.0, ry + 42.0), TEXT_SECONDARY);

                    let (st_txt, st_col) = match states.get(&s.service_name).copied().unwrap_or(WinServiceState::Other) {
                        WinServiceState::Running => ("En cours", ACCENT_EMERALD),
                        WinServiceState::Stopped => ("Arrêté", TEXT_SECONDARY),
                        WinServiceState::Paused => ("En pause", ACCENT_AMBER),
                        _ => ("Accès / N/A", TEXT_SECONDARY),
                    };
                    draw_text(rt, st_txt, &self.typo.body_bold, rect(x + 366.0, ry, x + 480.0, ry + row_h), st_col);
                    draw_text(rt, &s.description, &self.typo.small, rect(x + 486.0, ry + 12.0, x + w - 14.0, ry + row_h), TEXT_SECONDARY);
                    ry += row_h;
                }
                y + h + 12.0
            }
            ProcSubTab::RunningProcesses => {
                let procs = self.state.running_processes.clone();
                let count = procs.len().min(45);
                let row_h = 30.0;
                let h = 42.0 + count as f32 * row_h;
                fill_rounded_card(rt, rect(x, y, x + w, y + h), 10.0, BG_CARD, BORDER_SUBTLE);
                draw_text(rt, "PROCESSUS", &self.typo.eyebrow, rect(x + 14.0, y + 10.0, x + 300.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "PID", &self.typo.eyebrow, rect(x + 310.0, y + 10.0, x + 390.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "RAM", &self.typo.eyebrow, rect(x + 400.0, y + 10.0, x + 500.0, y + 30.0), TEXT_SECONDARY);
                draw_text(rt, "STATUT", &self.typo.eyebrow, rect(x + 510.0, y + 10.0, x + 700.0, y + 30.0), TEXT_SECONDARY);
                draw_line(rt, x + 12.0, y + 34.0, x + w - 12.0, y + 34.0, BORDER_SUBTLE, 1.0);

                let mut ry = y + 38.0;
                for p in procs.iter().take(count) {
                    draw_text(rt, &p.name, &self.typo.mono, rect(x + 14.0, ry, x + 300.0, ry + row_h), TEXT_PRIMARY);
                    draw_text(rt, &format!("{}", p.pid), &self.typo.mono, rect(x + 310.0, ry, x + 390.0, ry + row_h), TEXT_SECONDARY);
                    draw_text(rt, &format!("{:.1} Mo", p.ram_mb), &self.typo.mono, rect(x + 400.0, ry, x + 500.0, ry + row_h), ACCENT_CYAN);
                    let (st, sc) = if p.is_suspended_by_us {
                        ("SUSPENDU", ACCENT_AMBER)
                    } else if p.is_immutable_protected {
                        ("OS / ANTI-CHEAT", ACCENT_EMERALD)
                    } else if p.is_user_whitelisted {
                        ("WHITELIST", ACCENT_CYAN)
                    } else {
                        ("Normal", TEXT_SECONDARY)
                    };
                    draw_text(rt, st, &self.typo.eyebrow, rect(x + 510.0, ry, x + 700.0, ry + row_h), sc);
                    if !p.is_immutable_protected && !p.is_user_whitelisted {
                        let b = rect(x + w - 110.0, ry + 3.0, x + w - 14.0, ry + row_h - 3.0);
                        let h = self.register_hit(b, UiAction::AddWhitelist(p.name.clone()));
                        draw_button(rt, b, "+ Protéger", &self.typo.center_btn, BG_CARD_ELEVATED, ACCENT_CYAN, TEXT_PRIMARY, h);
                    }
                    ry += row_h;
                }
                y + h + 12.0
            }
            ProcSubTab::Whitelist => {
                let half = (w - 12.0) / 2.0;
                let left = rect(x, y, x + half, y + 430.0);
                fill_rounded_card(rt, left, 10.0, BG_CARD, ACCENT_EMERALD);
                draw_text(rt, "WHITELIST INVIOLABLE (SYSTÈME & ANTI-CHEAT)", &self.typo.eyebrow, rect(x + 14.0, y + 12.0, left.right - 14.0, y + 30.0), ACCENT_EMERALD);
                let mut ly = y + 38.0;
                for (name, cat) in immutable_whitelist_summary() {
                    draw_text(rt, name, &self.typo.mono, rect(x + 14.0, ly, left.right - 150.0, ly + 22.0), TEXT_PRIMARY);
                    draw_text(rt, cat, &self.typo.right_small, rect(left.right - 170.0, ly, left.right - 14.0, ly + 22.0), ACCENT_EMERALD);
                    ly += 24.0;
                }

                let rx = x + half + 12.0;
                let right = rect(rx, y, x + w, y + 430.0);
                fill_rounded_card(rt, right, 10.0, BG_CARD, BORDER_SUBTLE);
                draw_text(rt, "LISTE BLANCHE PERSONNALISÉE", &self.typo.eyebrow, rect(rx + 14.0, y + 12.0, right.right - 14.0, y + 30.0), TEXT_SECONDARY);
                let inp = rect(rx + 14.0, y + 38.0, right.right - 118.0, y + 68.0);
                let ih = self.register_hit(inp, UiAction::FocusField(FocusedInput::NewWhitelistExe));
                draw_text_input(
                    rt,
                    inp,
                    &self.new_whitelist_input,
                    "ex: spotify.exe",
                    self.focused_input == FocusedInput::NewWhitelistExe,
                    ih,
                    &self.typo.mono,
                );
                let abtn = rect(right.right - 108.0, y + 38.0, right.right - 14.0, y + 68.0);
                let ah = self.register_hit(abtn, UiAction::SubmitNewWhitelist);
                draw_button(rt, abtn, "+ Protéger", &self.typo.center_btn, ACCENT_EMERALD, ACCENT_EMERALD, TEXT_DARK, ah);

                let wl = self.state.config.user_whitelist.clone();
                let mut wy = y + 82.0;
                for item in wl {
                    draw_text(rt, &item, &self.typo.mono, rect(rx + 14.0, wy, right.right - 90.0, wy + 26.0), ACCENT_CYAN);
                    let rm = rect(right.right - 84.0, wy + 2.0, right.right - 14.0, wy + 24.0);
                    let rh = self.register_hit(rm, UiAction::RemoveWhitelist(item));
                    draw_button(rt, rm, "Retirer", &self.typo.center_btn, BG_CARD_ELEVATED, BORDER_BRIGHT, TEXT_SECONDARY, rh);
                    wy += 30.0;
                }
                y + 442.0
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ONGLET 4 : NETTOYAGE PC (100 % SÛR)
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_tab_cleaner(&mut self, rt: &ID2D1RenderTarget, x: f32, mut y: f32, w: f32) -> f32 {
        draw_text(
            rt,
            "NETTOYAGE PC — 100 % SÛR & APERÇU PRÉALABLE",
            &self.typo.title_md,
            rect(x, y, x + w, y + 24.0),
            TEXT_PRIMARY,
        );
        draw_text(
            rt,
            "Les fichiers verrouillés sont ignorés sans erreur et l'espace libéré est journalisé.",
            &self.typo.small,
            rect(x, y + 25.0, x + w, y + 43.0),
            TEXT_SECONDARY,
        );
        y += 50.0;

        let sel_bytes: u64 = self
            .state
            .clean_categories
            .iter()
            .filter(|c| c.selected)
            .map(|c| c.bytes_recoverable)
            .sum();
        let sel_files: u64 = self
            .state
            .clean_categories
            .iter()
            .filter(|c| c.selected)
            .map(|c| c.file_count)
            .sum();
        let any_scanned = self.state.clean_categories.iter().any(|c| c.scanned);

        let hero_h = if self.state.clean_scanning || self.state.clean_running {
            106.0
        } else {
            92.0
        };
        let hero_rc = rect(x, y, x + w, y + hero_h);
        fill_rounded_card(
            rt,
            hero_rc,
            11.0,
            BG_CARD,
            if self.state.clean_running {
                ACCENT_EMERALD
            } else if self.state.clean_scanning {
                ACCENT_CYAN
            } else {
                BORDER_BRIGHT
            },
        );
        draw_text(
            rt,
            "ESPACE RÉCUPÉRABLE SÉLECTIONNÉ",
            &self.typo.eyebrow,
            rect(x + 16.0, y + 12.0, x + w - 380.0, y + 28.0),
            TEXT_SECONDARY,
        );
        let big = if any_scanned {
            cleaner::format_bytes(sel_bytes)
        } else {
            "Cliquez sur Analyser".to_string()
        };
        draw_text(
            rt,
            &big,
            &self.typo.kpi,
            rect(x + 16.0, y + 30.0, x + w - 380.0, y + 60.0),
            ACCENT_EMERALD,
        );
        draw_text(
            rt,
            &format!(
                "{} fichier(s) ciblé(s)  •  Libéré cette session : {}",
                sel_files,
                cleaner::format_bytes(self.state.total_clean_freed_bytes)
            ),
            &self.typo.small,
            rect(x + 16.0, y + 64.0, x + w - 380.0, y + 84.0),
            TEXT_SECONDARY,
        );

        let scan_btn = rect(x + w - 366.0, y + 24.0, x + w - 208.0, y + 66.0);
        let sh = self.register_hit(scan_btn, UiAction::ScanClean);
        draw_button(
            rt,
            scan_btn,
            if self.state.clean_scanning {
                "ANALYSE..."
            } else {
                "ANALYSER LE PC"
            },
            &self.typo.center_btn,
            BG_CARD_ELEVATED,
            ACCENT_CYAN,
            TEXT_PRIMARY,
            sh,
        );
        let exec_btn = rect(x + w - 196.0, y + 24.0, x + w - 16.0, y + 66.0);
        let eh = self.register_hit(exec_btn, UiAction::ExecuteClean);
        draw_button(
            rt,
            exec_btn,
            if self.state.clean_running {
                "NETTOYAGE..."
            } else {
                "NETTOYER"
            },
            &self.typo.center_btn,
            ACCENT_EMERALD,
            ACCENT_EMERALD,
            TEXT_DARK,
            eh,
        );

        if self.state.clean_scanning || self.state.clean_running {
            draw_indeterminate_bar(
                rt,
                rect(x + 16.0, y + 88.0, x + w - 16.0, y + 95.0),
                self.anim_phase,
                if self.state.clean_running {
                    ACCENT_EMERALD
                } else {
                    ACCENT_CYAN
                },
            );
        }
        y += hero_h + 14.0;

        // Grille 2x3 des 6 catégories
        let cats = self.state.clean_categories.clone();
        let is_admin = self.state.capabilities.is_admin;
        let gap = 12.0;
        let cw = (w - gap) / 2.0;
        let ch = 104.0;

        for (i, cat) in cats.iter().enumerate() {
            let col = i % 2;
            let row = i / 2;
            let cx = x + (cw + gap) * col as f32;
            let cy = y + (ch + gap) * row as f32;
            let crc = rect(cx, cy, cx + cw, cy + ch);
            let hov = self.register_hit(crc, UiAction::ToggleCleanCat(cat.id));
            fill_rounded_card(
                rt,
                crc,
                10.0,
                if hov { BG_CARD_ELEVATED } else { BG_CARD },
                if cat.selected {
                    with_alpha(ACCENT_EMERALD, 0.55)
                } else {
                    BORDER_SUBTLE
                },
            );
            draw_checkbox(rt, cx + 14.0, cy + 14.0, cat.selected, hov);
            draw_text(
                rt,
                &cat.title,
                &self.typo.heading,
                rect(cx + 40.0, cy + 12.0, crc.right - 95.0, cy + 32.0),
                TEXT_PRIMARY,
            );
            let size_str = if cat.scanned {
                cleaner::format_bytes(cat.bytes_recoverable)
            } else {
                "—".to_string()
            };
            draw_text(
                rt,
                &size_str,
                &self.typo.right_body,
                rect(crc.right - 100.0, cy + 12.0, crc.right - 14.0, cy + 32.0),
                if cat.bytes_recoverable > 50 * 1024 * 1024 {
                    ACCENT_AMBER
                } else {
                    ACCENT_EMERALD
                },
            );
            draw_text(
                rt,
                &cat.subtitle,
                &self.typo.small,
                rect(cx + 14.0, cy + 38.0, crc.right - 14.0, cy + 72.0),
                TEXT_SECONDARY,
            );
            draw_text(
                rt,
                &cat.paths_summary,
                &self.typo.mono,
                rect(cx + 14.0, cy + 76.0, crc.right - 120.0, cy + 96.0),
                ACCENT_CYAN,
            );
            if cat.requires_admin && !is_admin {
                draw_text(
                    rt,
                    "ADMIN REQUIS",
                    &self.typo.right_small,
                    rect(crc.right - 120.0, cy + 76.0, crc.right - 14.0, cy + 96.0),
                    ACCENT_AMBER,
                );
            } else if cat.scanned {
                draw_text(
                    rt,
                    &format!("{} fichiers", cat.file_count),
                    &self.typo.right_small,
                    rect(crc.right - 120.0, cy + 76.0, crc.right - 14.0, cy + 96.0),
                    TEXT_SECONDARY,
                );
            }
        }
        y += ((cats.len() + 1) / 2) as f32 * (ch + gap) + 6.0;

        if let Some(ref rep) = self.state.last_clean_report {
            let rh = 44.0 + rep.details.len() as f32 * 20.0;
            fill_rounded_card(rt, rect(x, y, x + w, y + rh), 10.0, BG_CARD_ELEVATED, ACCENT_EMERALD);
            draw_text(
                rt,
                &format!(
                    "DERNIER NETTOYAGE : {} LIBÉRÉS ({} SUPPRIMÉS, {} VERROUILLÉS IGNORÉS)",
                    cleaner::format_bytes(rep.bytes_freed),
                    rep.files_deleted,
                    rep.files_skipped_locked
                ),
                &self.typo.eyebrow,
                rect(x + 14.0, y + 10.0, x + w - 14.0, y + 28.0),
                ACCENT_EMERALD,
            );
            let mut dy = y + 32.0;
            for line in &rep.details {
                draw_text(rt, &format!("• {}", line), &self.typo.small, rect(x + 14.0, dy, x + w - 14.0, dy + 18.0), TEXT_PRIMARY);
                dy += 20.0;
            }
            y += rh + 12.0;
        }
        y
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ONGLET 5 : MONITORING & PING (IPv4 + IPv6)
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_tab_monitoring(&mut self, rt: &ID2D1RenderTarget, x: f32, mut y: f32, w: f32) -> f32 {
        draw_text(
            rt,
            "MONITORING TEMPS RÉEL & LATENCE RÉSEAU (IPv4 / IPv6)",
            &self.typo.title_md,
            rect(x, y, x + w, y + 24.0),
            TEXT_PRIMARY,
        );
        draw_luminous_badge(
            rt,
            rect(x + w - 210.0, y, x + w, y + 24.0),
            "0 % IMPACT EN JEU (FERMÉ)",
            &self.typo.eyebrow,
            ACCENT_EMERALD,
            false,
        );
        y += 36.0;

        let gap = 12.0;
        let half = (w - gap) / 2.0;
        let card_h = 166.0;

        // Carte CPU + sparkline
        let c1 = rect(x, y, x + half, y + card_h);
        fill_rounded_card(rt, c1, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "PROCESSEUR (CPU)", &self.typo.eyebrow, rect(x + 14.0, y + 12.0, x + 200.0, y + 28.0), TEXT_SECONDARY);
        let cpu_hdr = match self.state.metrics.cpu_temp_c {
            Some(t) => format!("{:.1} %  •  {:.0} °C", self.state.metrics.cpu_usage_percent, t),
            None => format!("{:.1} %", self.state.metrics.cpu_usage_percent),
        };
        draw_text(
            rt,
            &cpu_hdr,
            &self.typo.right_body,
            rect(c1.right - 160.0, y + 10.0, c1.right - 14.0, y + 30.0),
            ACCENT_CYAN,
        );
        draw_progress_bar(rt, rect(x + 14.0, y + 36.0, c1.right - 14.0, y + 43.0), self.anim_cpu / 100.0, ACCENT_CYAN);
        self.draw_sparkline(rt, rect(x + 14.0, y + 54.0, c1.right - 14.0, c1.bottom - 14.0), &self.state.cpu_history, 100.0, ACCENT_CYAN);

        // Carte RAM + sparkline
        let c2 = rect(x + half + gap, y, x + w, y + card_h);
        fill_rounded_card(rt, c2, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "MÉMOIRE VIVE (RAM)", &self.typo.eyebrow, rect(c2.left + 14.0, y + 12.0, c2.left + 200.0, y + 28.0), TEXT_SECONDARY);
        draw_text(
            rt,
            &format!(
                "{:.1} / {:.1} Go ({:.0}%)",
                self.state.metrics.ram_used_gb,
                self.state.metrics.ram_total_gb,
                self.state.metrics.ram_usage_percent
            ),
            &self.typo.right_body,
            rect(c2.right - 200.0, y + 10.0, c2.right - 14.0, y + 30.0),
            ACCENT_EMERALD,
        );
        draw_progress_bar(rt, rect(c2.left + 14.0, y + 36.0, c2.right - 14.0, y + 43.0), self.anim_ram / 100.0, ACCENT_EMERALD);
        self.draw_sparkline(rt, rect(c2.left + 14.0, y + 54.0, c2.right - 14.0, c2.bottom - 14.0), &self.state.ram_history, 100.0, ACCENT_EMERALD);

        y += card_h + gap;

        // Carte GPU
        let c3 = rect(x, y, x + half, y + 212.0);
        fill_rounded_card(rt, c3, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "CARTE GRAPHIQUE (GPU)", &self.typo.eyebrow, rect(x + 14.0, y + 12.0, x + 220.0, y + 28.0), TEXT_SECONDARY);
        let gpu_pct = self
            .state
            .metrics
            .gpu_usage_percent
            .map(|g| format!("{:.0} %", g))
            .unwrap_or_else(|| "WDDM".to_string());
        draw_text(rt, &gpu_pct, &self.typo.right_body, rect(c3.right - 100.0, y + 10.0, c3.right - 14.0, y + 30.0), ACCENT_INDIGO);
        draw_progress_bar(rt, rect(x + 14.0, y + 36.0, c3.right - 14.0, y + 43.0), self.anim_gpu / 100.0, ACCENT_INDIGO);
        let gpu_info = format!(
            "{}  •  Temp : {}  •  VRAM : {}",
            self.state.capabilities.gpu_name,
            self.state.metrics.gpu_temp_c.map(|t| format!("{:.0} °C", t)).unwrap_or_else(|| "N/A".to_string()),
            match (self.state.metrics.gpu_vram_used_mb, self.state.metrics.gpu_vram_total_mb) {
                (Some(u), Some(t)) => format!("{} / {} Mo", u, t),
                _ => "N/A".to_string(),
            }
        );
        draw_text(rt, &gpu_info, &self.typo.small, rect(x + 14.0, y + 50.0, c3.right - 14.0, y + 68.0), TEXT_SECONDARY);
        self.draw_sparkline(rt, rect(x + 14.0, y + 74.0, c3.right - 14.0, c3.bottom - 14.0), &self.state.gpu_history, 100.0, ACCENT_INDIGO);

        // Carte Test Ping ICMP natif IPv4 & IPv6
        let c4 = rect(x + half + gap, y, x + w, y + 212.0);
        fill_rounded_card(rt, c4, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "TEST PING / LATENCE RÉSEAU (ICMP IPv4 & IPv6)", &self.typo.eyebrow, rect(c4.left + 14.0, y + 12.0, c4.right - 14.0, y + 28.0), TEXT_SECONDARY);

        let presets = [
            ("1.1.1.1 (v4)", "1.1.1.1"),
            ("Cloudflare v6", "2606:4700:4700::1111"),
            ("8.8.8.8", "8.8.8.8"),
            ("9.9.9.9", "9.9.9.9"),
        ];
        let pbw = (half - 28.0 - 18.0) / 4.0;
        for (i, (lbl, host)) in presets.iter().enumerate() {
            let b = rect(c4.left + 14.0 + (pbw + 6.0) * i as f32, y + 36.0, c4.left + 14.0 + (pbw + 6.0) * i as f32 + pbw, y + 62.0);
            let hov = self.register_hit(b, UiAction::QuickPing((*lbl).to_string(), (*host).to_string()));
            draw_button(rt, b, lbl, &self.typo.center_btn, BG_CARD_ELEVATED, BORDER_BRIGHT, TEXT_PRIMARY, hov);
        }

        let inp = rect(c4.left + 14.0, y + 72.0, c4.right - 108.0, y + 100.0);
        let ih = self.register_hit(inp, UiAction::FocusField(FocusedInput::CustomPingHost));
        draw_text_input(
            rt,
            inp,
            &self.ping_host_input,
            "IPv4, IPv6 ou domaine...",
            self.focused_input == FocusedInput::CustomPingHost,
            ih,
            &self.typo.mono,
        );
        let tbtn = rect(c4.right - 98.0, y + 72.0, c4.right - 14.0, y + 100.0);
        let th = self.register_hit(tbtn, UiAction::TriggerCustomPing);
        draw_button(
            rt,
            tbtn,
            if self.state.ping_running { "..." } else { "Tester" },
            &self.typo.center_btn,
            ACCENT_EMERALD,
            ACCENT_EMERALD,
            TEXT_DARK,
            th,
        );

        let mut py = y + 112.0;
        if self.state.ping_results.is_empty() {
            draw_text(rt, "Lancez un test pour mesurer latence (min/moy/max), gigue et perte de paquets.", &self.typo.small, rect(c4.left + 14.0, py, c4.right - 14.0, py + 40.0), TEXT_SECONDARY);
        } else {
            for r in self.state.ping_results.iter().take(4) {
                let (line, col) = if let Some(ref err) = r.error {
                    (format!("• {} — {}", r.target_name, err), ACCENT_CRIMSON)
                } else {
                    let c = if r.avg_ms < 35.0 && r.loss_percent == 0.0 {
                        ACCENT_EMERALD
                    } else if r.avg_ms < 75.0 {
                        ACCENT_AMBER
                    } else {
                        ACCENT_CRIMSON
                    };
                    (
                        format!(
                            "• {} ({}) : {:.1} ms (min {:.0}/max {:.0}, gigue {:.1}) • perte {:.0}%",
                            r.target_name, r.resolved_ip, r.avg_ms, r.min_ms, r.max_ms, r.jitter_ms, r.loss_percent
                        ),
                        c,
                    )
                };
                draw_text(rt, &line, &self.typo.small, rect(c4.left + 14.0, py, c4.right - 14.0, py + 20.0), col);
                py += 22.0;
            }
        }

        y + 224.0
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ONGLET 6 : PARAMÈTRES & JOURNAUX
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_tab_settings(&mut self, rt: &ID2D1RenderTarget, x: f32, mut y: f32, w: f32) -> f32 {
        draw_text(
            rt,
            "PARAMÈTRES, RÉVERSIBILITÉ & JOURNAUX",
            &self.typo.title_md,
            rect(x, y, x + w, y + 24.0),
            TEXT_PRIMARY,
        );
        y += 34.0;

        let gap = 12.0;
        let half = (w - gap) / 2.0;
        let card_h = 152.0;

        // Paramètres démarrage
        let c1 = rect(x, y, x + half, y + card_h);
        fill_rounded_card(rt, c1, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "COMPORTEMENT & DÉMARRAGE", &self.typo.eyebrow, rect(x + 14.0, y + 12.0, c1.right - 14.0, y + 28.0), TEXT_SECONDARY);

        let toggles = [
            (
                self.state.config.launch_with_windows,
                "Lancer automatiquement avec Windows",
                UiAction::ToggleSettingLaunchWindows,
            ),
            (
                self.state.config.start_minimized_to_tray,
                "Démarrer le daemon réduit dans le Tray",
                UiAction::ToggleSettingStartMin,
            ),
            (
                self.state.config.auto_crash_recovery,
                "Crash-Recovery automatique au démarrage",
                UiAction::ToggleSettingAutoCrash,
            ),
        ];
        let mut ty = y + 38.0;
        for (val, label, act) in toggles {
            let row = rect(x + 14.0, ty, c1.right - 14.0, ty + 28.0);
            let h = self.register_hit(row, act);
            draw_checkbox(rt, x + 14.0, ty + 4.0, val, h);
            draw_text(rt, label, &self.typo.body, rect(x + 40.0, ty + 3.0, c1.right - 14.0, ty + 26.0), TEXT_PRIMARY);
            ty += 34.0;
        }

        // Snapshot & Restauration
        let c2 = rect(x + half + gap, y, x + w, y + card_h);
        fill_rounded_card(rt, c2, 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "SNAPSHOT ATOMIQUE (MoveFileExW) & RESTAURATION", &self.typo.eyebrow, rect(c2.left + 14.0, y + 12.0, c2.right - 14.0, y + 28.0), TEXT_SECONDARY);
        draw_text(rt, &self.state.recovery_path, &self.typo.mono, rect(c2.left + 14.0, y + 34.0, c2.right - 14.0, y + 54.0), TEXT_SECONDARY);
        let st_line = self
            .state
            .recovery_file_summary
            .as_deref()
            .unwrap_or("État propre : aucun snapshot non restauré sur disque.");
        draw_text(
            rt,
            st_line,
            &self.typo.small,
            rect(c2.left + 14.0, y + 58.0, c2.right - 14.0, y + 92.0),
            if self.state.recovery_file_summary.is_some() {
                ACCENT_AMBER
            } else {
                ACCENT_EMERALD
            },
        );
        let sb = rect(c2.left + 14.0, y + 102.0, c2.left + half * 0.48, y + 136.0);
        let sh = self.register_hit(sb, UiAction::SaveSnapshot);
        draw_button(rt, sb, "Sauvegarder Snapshot", &self.typo.center_btn, BG_CARD_ELEVATED, ACCENT_CYAN, TEXT_PRIMARY, sh);

        let rb = rect(sb.right + 10.0, y + 102.0, c2.right - 14.0, y + 136.0);
        let rh = self.register_hit(rb, UiAction::RestoreInitial);
        draw_button(rt, rb, "Restaurer l'état initial", &self.typo.center_btn, ACCENT_EMERALD, ACCENT_EMERALD, TEXT_DARK, rh);

        y += card_h + 14.0;

        // Journaux détaillés
        let logs = self.state.logs.clone();
        let filtered: Vec<_> = logs
            .iter()
            .rev()
            .filter(|e| self.log_filter.map(|f| e.level == f).unwrap_or(true))
            .take(30)
            .collect();
        let log_h = 56.0 + (filtered.len().max(4) as f32) * 22.0;
        fill_rounded_card(rt, rect(x, y, x + w, y + log_h), 10.0, BG_CARD, BORDER_SUBTLE);
        draw_text(rt, "JOURNAL TRANSPARENT DES ACTIONS", &self.typo.eyebrow, rect(x + 14.0, y + 14.0, x + 290.0, y + 32.0), TEXT_PRIMARY);

        let mut fx = x + 300.0;
        for (lvl, lbl) in [
            (None, "Tous"),
            (Some(LogLevel::Success), "Succès"),
            (Some(LogLevel::Warning), "Alertes"),
            (Some(LogLevel::Error), "Erreurs"),
        ] {
            let b = rect(fx, y + 10.0, fx + 68.0, y + 34.0);
            let sel = self.log_filter == lvl;
            let h = self.register_hit(b, UiAction::SetLogFilter(lvl));
            draw_button(
                rt,
                b,
                lbl,
                &self.typo.center_btn,
                if sel { BG_CARD_ELEVATED } else { BG_OLED },
                if sel { ACCENT_CYAN } else { BORDER_SUBTLE },
                if sel { ACCENT_CYAN } else { TEXT_SECONDARY },
                h,
            );
            fx += 74.0;
        }
        let clr = rect(x + w - 92.0, y + 10.0, x + w - 14.0, y + 34.0);
        let ch = self.register_hit(clr, UiAction::ClearLogs);
        draw_button(rt, clr, "Effacer", &self.typo.center_btn, BG_CARD_ELEVATED, BORDER_BRIGHT, TEXT_SECONDARY, ch);

        draw_line(rt, x + 12.0, y + 42.0, x + w - 12.0, y + 42.0, BORDER_SUBTLE, 1.0);
        let mut ly = y + 48.0;
        for entry in filtered {
            let col = match entry.level {
                LogLevel::Info => TEXT_SECONDARY,
                LogLevel::Success => ACCENT_EMERALD,
                LogLevel::Warning => ACCENT_AMBER,
                LogLevel::Error => ACCENT_CRIMSON,
            };
            let ts = entry.timestamp.format("%H:%M:%S").to_string();
            draw_text(rt, &ts, &self.typo.mono, rect(x + 14.0, ly, x + 82.0, ly + 20.0), TEXT_SECONDARY);
            draw_text(rt, &format!("[{}]", entry.category), &self.typo.mono, rect(x + 84.0, ly, x + 210.0, ly + 20.0), col);
            draw_text(rt, &entry.message, &self.typo.small, rect(x + 214.0, ly + 2.0, x + w - 14.0, ly + 20.0), TEXT_PRIMARY);
            ly += 22.0;
        }
        y + log_h + 12.0
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PRIMITIVES GRAPHIQUES DIRECT2D (JAUGES RADIALES, SPARKLINES, ICÔNES)
    // ═══════════════════════════════════════════════════════════════════════
    fn draw_radial_kpi_card(
        &self,
        rt: &ID2D1RenderTarget,
        rc: D2D_RECT_F,
        title: &str,
        percent: f32,
        big_label: &str,
        sub: &str,
        accent: D2D1_COLOR_F,
    ) {
        fill_rounded_card(rt, rc, 10.0, BG_CARD, BORDER_SUBTLE);
        let cx = rc.left + 40.0;
        let cy = (rc.top + rc.bottom) * 0.5;
        self.draw_radial_gauge(rt, cx, cy, 26.0, percent, big_label, accent);

        let tx = rc.left + 76.0;
        draw_text(rt, title, &self.typo.eyebrow, rect(tx, rc.top + 14.0, rc.right - 8.0, rc.top + 30.0), TEXT_SECONDARY);
        draw_text(rt, big_label, &self.typo.kpi, rect(tx, rc.top + 34.0, rc.right - 8.0, rc.top + 66.0), accent);
        draw_text(rt, sub, &self.typo.small, rect(tx, rc.top + 68.0, rc.right - 8.0, rc.bottom - 8.0), TEXT_SECONDARY);
    }

    fn draw_radial_gauge(
        &self,
        rt: &ID2D1RenderTarget,
        cx: f32,
        cy: f32,
        radius: f32,
        percent: f32,
        center_text: &str,
        accent: D2D1_COLOR_F,
    ) {
        let ellipse = D2D1_ELLIPSE {
            point: pt(cx, cy),
            radiusX: radius,
            radiusY: radius,
        };
        if let Some(track) = solid_brush(rt, BORDER_SUBTLE) {
            unsafe {
                rt.DrawEllipse(&ellipse, &track, 5.0, None);
            }
        }

        let frac = (percent / 100.0).clamp(0.0, 0.999);
        if frac > 0.005 {
            if let Ok(geo) = unsafe { self.d2d_factory.CreatePathGeometry() } {
                if let Ok(sink) = unsafe { geo.Open() } {
                    let start_a = -PI * 0.5;
                    let end_a = start_a + frac * 2.0 * PI;
                    let p0 = pt(cx + radius * start_a.cos(), cy + radius * start_a.sin());
                    let p1 = pt(cx + radius * end_a.cos(), cy + radius * end_a.sin());
                    unsafe {
                        sink.BeginFigure(p0, D2D1_FIGURE_BEGIN_HOLLOW);
                        sink.AddArc(&D2D1_ARC_SEGMENT {
                            point: p1,
                            size: D2D_SIZE_F {
                                width: radius,
                                height: radius,
                            },
                            rotationAngle: 0.0,
                            sweepDirection: D2D1_SWEEP_DIRECTION_CLOCKWISE,
                            arcSize: if frac > 0.5 {
                                D2D1_ARC_SIZE_LARGE
                            } else {
                                D2D1_ARC_SIZE_SMALL
                            },
                        });
                        sink.EndFigure(D2D1_FIGURE_END_OPEN);
                        let _ = sink.Close();
                    }
                    if let Some(halo) = solid_brush(rt, with_alpha(accent, 0.22)) {
                        unsafe {
                            rt.DrawGeometry(&geo, &halo, 9.0, None);
                        }
                    }
                    if let Some(stroke) = solid_brush(rt, accent) {
                        unsafe {
                            rt.DrawGeometry(&geo, &stroke, 5.0, None);
                        }
                    }
                }
            }
        }

        draw_text(
            rt,
            center_text,
            &self.typo.center_gauge,
            rect(cx - radius, cy - 12.0, cx + radius, cy + 12.0),
            TEXT_PRIMARY,
        );
    }

    fn draw_sparkline(
        &self,
        rt: &ID2D1RenderTarget,
        rc: D2D_RECT_F,
        data: &[f32],
        max_val: f32,
        color: D2D1_COLOR_F,
    ) {
        fill_rounded_card(rt, rc, 7.0, rgba(9, 13, 21, 1.0), BORDER_SUBTLE);
        let h = rc.bottom - rc.top;
        let w = rc.right - rc.left;
        for f in [0.25, 0.5, 0.75] {
            let gy = rc.bottom - h * f;
            draw_line(rt, rc.left + 2.0, gy, rc.right - 2.0, gy, rgba(120, 140, 165, 0.12), 1.0);
        }
        if data.len() < 2 {
            draw_text(rt, "En attente de mesures...", &self.typo.center_gauge, rc, TEXT_SECONDARY);
            return;
        }

        let step = (w - 8.0) / (data.len() - 1) as f32;
        let points: Vec<D2D_POINT_2F> = data
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let norm = (v / max_val.max(1.0)).clamp(0.0, 1.0);
                pt(rc.left + 4.0 + i as f32 * step, rc.bottom - 4.0 - norm * (h - 8.0))
            })
            .collect();

        // Aire translucide sous la courbe
        if let Ok(area) = unsafe { self.d2d_factory.CreatePathGeometry() } {
            if let Ok(sink) = unsafe { area.Open() } {
                unsafe {
                    sink.BeginFigure(pt(points[0].x, rc.bottom - 2.0), D2D1_FIGURE_BEGIN_FILLED);
                    for &p in &points {
                        sink.AddLine(p);
                    }
                    sink.AddLine(pt(points[points.len() - 1].x, rc.bottom - 2.0));
                    sink.EndFigure(D2D1_FIGURE_END_CLOSED);
                    let _ = sink.Close();
                }
                if let Some(fill) = solid_brush(rt, with_alpha(color, 0.16)) {
                    unsafe {
                        rt.FillGeometry(&area, &fill, None);
                    }
                }
            }
        }

        if let Some(brush) = solid_brush(rt, color) {
            for seg in points.windows(2) {
                unsafe {
                    rt.DrawLine(seg[0], seg[1], &brush, 2.0, None);
                }
            }
        }
    }

    fn draw_nav_icon(&self, rt: &ID2D1RenderTarget, r: D2D_RECT_F, icon: NavIcon, color: D2D1_COLOR_F) {
        let Some(brush) = solid_brush(rt, color) else {
            return;
        };
        let w = r.right - r.left;
        let h = r.bottom - r.top;
        let cx = (r.left + r.right) * 0.5;
        let cy = (r.top + r.bottom) * 0.5;

        let draw_poly = |pts: &[D2D_POINT_2F], closed: bool| {
            if let Ok(geo) = unsafe { self.d2d_factory.CreatePathGeometry() } {
                if let Ok(sink) = unsafe { geo.Open() } {
                    unsafe {
                        sink.BeginFigure(pts[0], D2D1_FIGURE_BEGIN_HOLLOW);
                        for &p in &pts[1..] {
                            sink.AddLine(p);
                        }
                        sink.EndFigure(if closed {
                            D2D1_FIGURE_END_CLOSED
                        } else {
                            D2D1_FIGURE_END_OPEN
                        });
                        let _ = sink.Close();
                        rt.DrawGeometry(&geo, &brush, 1.5, None);
                    }
                }
            }
        };

        match icon {
            NavIcon::Bolt => {
                draw_poly(
                    &[
                        pt(r.left + w * 0.58, r.top + h * 0.05),
                        pt(r.left + w * 0.18, r.top + h * 0.56),
                        pt(r.left + w * 0.52, r.top + h * 0.56),
                        pt(r.left + w * 0.42, r.top + h * 0.95),
                        pt(r.left + w * 0.82, r.top + h * 0.44),
                        pt(r.left + w * 0.48, r.top + h * 0.44),
                    ],
                    true,
                );
            }
            NavIcon::Gamepad => {
                let body = D2D1_ROUNDED_RECT {
                    rect: rect(r.left + 1.0, cy - h * 0.28, r.right - 1.0, cy + h * 0.28),
                    radiusX: 4.0,
                    radiusY: 4.0,
                };
                unsafe {
                    rt.DrawRoundedRectangle(&body, &brush, 1.5, None);
                    rt.DrawLine(pt(r.left + w * 0.25, cy), pt(r.left + w * 0.45, cy), &brush, 1.4, None);
                    rt.DrawLine(pt(r.left + w * 0.35, cy - 2.5), pt(r.left + w * 0.35, cy + 2.5), &brush, 1.4, None);
                    rt.FillEllipse(
                        &D2D1_ELLIPSE {
                            point: pt(r.right - w * 0.30, cy - 1.5),
                            radiusX: 1.3,
                            radiusY: 1.3,
                        },
                        &brush,
                    );
                    rt.FillEllipse(
                        &D2D1_ELLIPSE {
                            point: pt(r.right - w * 0.20, cy + 1.5),
                            radiusX: 1.3,
                            radiusY: 1.3,
                        },
                        &brush,
                    );
                }
            }
            NavIcon::Layers => {
                for f in [0.22, 0.5, 0.78] {
                    let y = r.top + h * f;
                    unsafe {
                        rt.DrawLine(pt(r.left + 1.5, y), pt(r.right - 1.5, y), &brush, 1.6, None);
                    }
                }
            }
            NavIcon::SparkClean => {
                draw_poly(
                    &[
                        pt(cx, r.top + 1.0),
                        pt(cx + w * 0.16, cy - h * 0.16),
                        pt(r.right - 1.0, cy),
                        pt(cx + w * 0.16, cy + h * 0.16),
                        pt(cx, r.bottom - 1.0),
                        pt(cx - w * 0.16, cy + h * 0.16),
                        pt(r.left + 1.0, cy),
                        pt(cx - w * 0.16, cy - h * 0.16),
                    ],
                    true,
                );
            }
            NavIcon::Pulse => {
                draw_poly(
                    &[
                        pt(r.left + 1.0, cy),
                        pt(r.left + w * 0.28, cy),
                        pt(r.left + w * 0.42, r.top + h * 0.15),
                        pt(r.left + w * 0.60, r.bottom - h * 0.15),
                        pt(r.left + w * 0.74, cy),
                        pt(r.right - 1.0, cy),
                    ],
                    false,
                );
            }
            NavIcon::Settings => unsafe {
                rt.DrawEllipse(
                    &D2D1_ELLIPSE {
                        point: pt(cx, cy),
                        radiusX: w * 0.34,
                        radiusY: h * 0.34,
                    },
                    &brush,
                    1.6,
                    None,
                );
                rt.FillEllipse(
                    &D2D1_ELLIPSE {
                        point: pt(cx, cy),
                        radiusX: w * 0.12,
                        radiusY: h * 0.12,
                    },
                    &brush,
                );
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS DIRECT2D & DIALOGUE NATIF WIN32
// ═══════════════════════════════════════════════════════════════════════════

fn pt(x: f32, y: f32) -> D2D_POINT_2F {
    D2D_POINT_2F { x, y }
}

fn rect(left: f32, top: f32, right: f32, bottom: f32) -> D2D_RECT_F {
    D2D_RECT_F {
        left,
        top,
        right,
        bottom,
    }
}

fn with_alpha(mut c: D2D1_COLOR_F, a: f32) -> D2D1_COLOR_F {
    c.a = a;
    c
}

fn solid_brush(rt: &ID2D1RenderTarget, color: D2D1_COLOR_F) -> Option<ID2D1SolidColorBrush> {
    unsafe { rt.CreateSolidColorBrush(&color, None).ok() }
}

fn fill_rect(rt: &ID2D1RenderTarget, r: D2D_RECT_F, color: D2D1_COLOR_F) {
    if let Some(b) = solid_brush(rt, color) {
        unsafe {
            rt.FillRectangle(&r, &b);
        }
    }
}

fn fill_rounded_rect(rt: &ID2D1RenderTarget, r: D2D_RECT_F, radius: f32, color: D2D1_COLOR_F) {
    if let Some(b) = solid_brush(rt, color) {
        let rr = D2D1_ROUNDED_RECT {
            rect: r,
            radiusX: radius,
            radiusY: radius,
        };
        unsafe {
            rt.FillRoundedRectangle(&rr, &b);
        }
    }
}

fn fill_rounded_card(
    rt: &ID2D1RenderTarget,
    r: D2D_RECT_F,
    radius: f32,
    fill: D2D1_COLOR_F,
    border: D2D1_COLOR_F,
) {
    let rr = D2D1_ROUNDED_RECT {
        rect: r,
        radiusX: radius,
        radiusY: radius,
    };
    if let Some(fb) = solid_brush(rt, fill) {
        unsafe {
            rt.FillRoundedRectangle(&rr, &fb);
        }
    }
    if radius >= 8.0 && (r.right - r.left) > radius * 2.0 {
        draw_line(
            rt,
            r.left + radius * 0.6,
            r.top + 1.0,
            r.right - radius * 0.6,
            r.top + 1.0,
            BORDER_ZENITHAL,
            1.0,
        );
    }
    if let Some(sb) = solid_brush(rt, border) {
        unsafe {
            rt.DrawRoundedRectangle(&rr, &sb, 1.0, None);
        }
    }
}

fn draw_line(
    rt: &ID2D1RenderTarget,
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
    color: D2D1_COLOR_F,
    width: f32,
) {
    if let Some(b) = solid_brush(rt, color) {
        unsafe {
            rt.DrawLine(pt(x1, y1), pt(x2, y2), &b, width, None);
        }
    }
}

fn draw_text(
    rt: &ID2D1RenderTarget,
    text: &str,
    fmt: &IDWriteTextFormat,
    r: D2D_RECT_F,
    color: D2D1_COLOR_F,
) {
    if let Some(b) = solid_brush(rt, color) {
        let wide: Vec<u16> = text.encode_utf16().collect();
        unsafe {
            rt.DrawText(&wide, fmt, &r, &b, D2D1_DRAW_TEXT_OPTIONS_CLIP, Default::default());
        }
    }
}

fn draw_glow_dot(rt: &ID2D1RenderTarget, cx: f32, cy: f32, color: D2D1_COLOR_F, pulse: bool) {
    if let Some(halo) = solid_brush(rt, with_alpha(color, if pulse { 0.35 } else { 0.18 })) {
        unsafe {
            rt.FillEllipse(
                &D2D1_ELLIPSE {
                    point: pt(cx, cy),
                    radiusX: 5.5,
                    radiusY: 5.5,
                },
                &halo,
            );
        }
    }
    if let Some(core) = solid_brush(rt, color) {
        unsafe {
            rt.FillEllipse(
                &D2D1_ELLIPSE {
                    point: pt(cx, cy),
                    radiusX: 3.0,
                    radiusY: 3.0,
                },
                &core,
            );
        }
    }
}

fn draw_luminous_badge(
    rt: &ID2D1RenderTarget,
    rc: D2D_RECT_F,
    label: &str,
    fmt: &IDWriteTextFormat,
    color: D2D1_COLOR_F,
    pulse: bool,
) {
    fill_rounded_card(rt, rc, 6.0, with_alpha(color, 0.11), with_alpha(color, 0.72));
    let cy = (rc.top + rc.bottom) * 0.5;
    draw_glow_dot(rt, rc.left + 12.0, cy, color, pulse);
    draw_text(rt, label, fmt, rect(rc.left + 22.0, rc.top, rc.right - 6.0, rc.bottom), color);
}

#[allow(clippy::too_many_arguments)]
fn draw_button(
    rt: &ID2D1RenderTarget,
    rc: D2D_RECT_F,
    label: &str,
    fmt: &IDWriteTextFormat,
    fill: D2D1_COLOR_F,
    border: D2D1_COLOR_F,
    text_color: D2D1_COLOR_F,
    hovered: bool,
) {
    let f = if hovered {
        D2D1_COLOR_F {
            r: (fill.r + 0.06).min(1.0),
            g: (fill.g + 0.06).min(1.0),
            b: (fill.b + 0.06).min(1.0),
            a: fill.a,
        }
    } else {
        fill
    };
    fill_rounded_card(rt, rc, 7.0, f, if hovered { ACCENT_CYAN } else { border });
    draw_text(rt, label, fmt, rc, text_color);
}

fn draw_checkbox(rt: &ID2D1RenderTarget, x: f32, y: f32, checked: bool, hovered: bool) {
    let r = rect(x, y, x + 18.0, y + 18.0);
    fill_rounded_card(
        rt,
        r,
        4.0,
        if checked { ACCENT_EMERALD } else { BG_OLED },
        if checked {
            ACCENT_EMERALD
        } else if hovered {
            ACCENT_CYAN
        } else {
            BORDER_BRIGHT
        },
    );
    if checked {
        draw_line(rt, x + 4.0, y + 9.5, x + 7.5, y + 13.0, TEXT_DARK, 2.0);
        draw_line(rt, x + 7.5, y + 13.0, x + 14.0, y + 5.0, TEXT_DARK, 2.0);
    }
}

fn draw_text_input(
    rt: &ID2D1RenderTarget,
    rc: D2D_RECT_F,
    value: &str,
    placeholder: &str,
    focused: bool,
    hovered: bool,
    fmt: &IDWriteTextFormat,
) {
    fill_rounded_card(
        rt,
        rc,
        6.0,
        BG_OLED,
        if focused {
            ACCENT_EMERALD
        } else if hovered {
            ACCENT_CYAN
        } else {
            BORDER_BRIGHT
        },
    );
    let shown = if value.is_empty() && !focused {
        placeholder.to_string()
    } else if focused {
        format!("{}|", value)
    } else {
        value.to_string()
    };
    draw_text(
        rt,
        &shown,
        fmt,
        rect(rc.left + 8.0, rc.top, rc.right - 8.0, rc.bottom),
        if value.is_empty() && !focused {
            TEXT_SECONDARY
        } else {
            TEXT_PRIMARY
        },
    );
}

fn draw_progress_bar(rt: &ID2D1RenderTarget, rc: D2D_RECT_F, frac: f32, color: D2D1_COLOR_F) {
    fill_rounded_rect(rt, rc, 3.5, BG_OLED);
    let fw = (rc.right - rc.left) * frac.clamp(0.0, 1.0);
    if fw > 1.0 {
        fill_rounded_rect(rt, rect(rc.left, rc.top, rc.left + fw, rc.bottom), 3.5, color);
    }
}

fn draw_indeterminate_bar(rt: &ID2D1RenderTarget, rc: D2D_RECT_F, phase: f32, color: D2D1_COLOR_F) {
    fill_rounded_rect(rt, rc, 3.0, BG_OLED);
    let w = rc.right - rc.left;
    let sw = w * 0.28;
    let sx = rc.left + (w + sw) * phase - sw;
    let left = sx.max(rc.left);
    let right = (sx + sw).min(rc.right);
    if right > left {
        fill_rounded_rect(rt, rect(left, rc.top, right, rc.bottom), 3.0, color);
    }
}

/// Boîte de dialogue native Win32 (`GetOpenFileNameW`) pour sélectionner un `.exe` de jeu.
fn pick_exe_filename(owner: HWND) -> Option<String> {
    let mut file_buf = [0u16; 260];
    let filter: Vec<u16> = "Exécutables (*.exe)\0*.exe\0Tous les fichiers (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file_buf.as_mut_ptr()),
        nMaxFile: file_buf.len() as u32,
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    let ok = unsafe { GetOpenFileNameW(&mut ofn).as_bool() };
    if !ok {
        return None;
    }
    let end = file_buf.iter().position(|&c| c == 0).unwrap_or(file_buf.len());
    let full = String::from_utf16_lossy(&file_buf[..end]);
    Path::new(&full)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}
