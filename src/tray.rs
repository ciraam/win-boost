//! Intégration native de la barre des tâches Windows (System Tray).
//!
//! Fournit :
//! - Une icône générée procéduralement (change de couleur quand le Boost est actif)
//! - Un menu contextuel clic droit rapide (Boost ON/OFF, Profil, Ouvrir, Quitter)
//! - Un pont d'événements pour contrôler l'application même lorsque la fenêtre est cachée

use muda::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::models::ProfileId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    ToggleBoost,
    SelectProfile(ProfileId),
    ShowDashboard,
    QuitAndRestore,
}

pub struct TrayController {
    tray: TrayIcon,
    id_toggle_boost: MenuId,
    id_prof_balanced: MenuId,
    id_prof_competitive: MenuId,
    id_prof_silent: MenuId,
    id_show: MenuId,
    id_quit: MenuId,
    toggle_item: MenuItem,
}

impl TrayController {
    pub fn create() -> Result<Self, String> {
        let menu = Menu::new();

        let toggle_item = MenuItem::new("Activer le Boost", true, None);
        let id_toggle_boost = toggle_item.id().clone();

        let prof_balanced = MenuItem::new("Équilibré", true, None);
        let id_prof_balanced = prof_balanced.id().clone();
        let prof_competitive = MenuItem::new("Compétitif / Max FPS", true, None);
        let id_prof_competitive = prof_competitive.id().clone();
        let prof_silent = MenuItem::new("Silencieux / Laptop", true, None);
        let id_prof_silent = prof_silent.id().clone();

        let profile_submenu = Submenu::with_items(
            "Changer de profil",
            true,
            &[&prof_balanced, &prof_competitive, &prof_silent],
        )
        .map_err(|e| format!("Création sous-menu Tray: {}", e))?;

        let show_item = MenuItem::new("Ouvrir le tableau de bord", true, None);
        let id_show = show_item.id().clone();

        let quit_item = MenuItem::new("Quitter (restaurer l'état)", true, None);
        let id_quit = quit_item.id().clone();

        menu.append_items(&[
            &toggle_item,
            &profile_submenu,
            &PredefinedMenuItem::separator(),
            &show_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ])
        .map_err(|e| format!("Construction menu Tray: {}", e))?;

        let icon = build_tray_icon(false)?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("WinBoost — Prêt (Auto-Boost actif)")
            .with_icon(icon)
            .build()
            .map_err(|e| format!("Création icône Tray impossible: {}", e))?;

        Ok(Self {
            tray,
            id_toggle_boost,
            id_prof_balanced,
            id_prof_competitive,
            id_prof_silent,
            id_show,
            id_quit,
            toggle_item,
        })
    }

    /// Met à jour l'icône, l'infobulle et le libellé du bouton Boost dans le System Tray.
    pub fn update_status(&self, boost_active: bool, profile_name: &str, game_name: Option<&str>) {
        if let Ok(icon) = build_tray_icon(boost_active) {
            let _ = self.tray.set_icon(Some(icon));
        }
        let tooltip = if boost_active {
            if let Some(g) = game_name {
                format!("WinBoost — BOOST ACTIF : {} ({})", g, profile_name)
            } else {
                format!("WinBoost — BOOST ACTIF ({})", profile_name)
            }
        } else {
            format!("WinBoost — Veille ({})", profile_name)
        };
        let _ = self.tray.set_tooltip(Some(tooltip));
        self.toggle_item.set_text(if boost_active {
            "Désactiver le Boost (restaurer)"
        } else {
            "Activer le Boost"
        });
    }

    /// Dépile les événements clics & menu du System Tray sans bloquer.
    pub fn poll_actions(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();

        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == self.id_toggle_boost {
                actions.push(TrayAction::ToggleBoost);
            } else if event.id == self.id_prof_balanced {
                actions.push(TrayAction::SelectProfile(ProfileId::Balanced));
            } else if event.id == self.id_prof_competitive {
                actions.push(TrayAction::SelectProfile(ProfileId::Competitive));
            } else if event.id == self.id_prof_silent {
                actions.push(TrayAction::SelectProfile(ProfileId::SilentLaptop));
            } else if event.id == self.id_show {
                actions.push(TrayAction::ShowDashboard);
            } else if event.id == self.id_quit {
                actions.push(TrayAction::QuitAndRestore);
            }
        }

        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
                | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                } => {
                    actions.push(TrayAction::ShowDashboard);
                }
                _ => {}
            }
        }

        actions
    }
}

/// Génère procéduralement une icône 32x32 nette (éclair stylisé sur badge sombre).
/// Vert émeraude lumineux lorsque le Boost est actif, cyan sobre en veille.
pub fn build_tray_icon(boost_active: bool) -> Result<Icon, String> {
    let size = 32usize;
    let mut rgba = vec![0u8; size * size * 4];

    let bg = if boost_active {
        [10u8, 36, 30, 255]
    } else {
        [18u8, 24, 38, 255]
    };
    let ring = if boost_active {
        [0u8, 224, 168, 255]
    } else {
        [56u8, 189, 248, 255]
    };
    let bolt = if boost_active {
        [110u8, 255, 210, 255]
    } else {
        [226u8, 238, 252, 255]
    };

    let cx = 15.5f32;
    let cy = 15.5f32;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let r = (dx * dx + dy * dy).sqrt();
            let idx = (y * size + x) * 4;

            if r > 15.0 {
                rgba[idx..idx + 4].copy_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            let mut px = if r >= 12.2 { ring } else { bg };

            // Forme d'éclair centré (symbole de performance instantanée)
            let fx = x as f32;
            let fy = y as f32;
            let in_upper_bolt =
                fy >= 6.0 && fy <= 16.5 && fx >= (18.5 - (fy - 6.0) * 0.68) && fx <= (21.5 - (fy - 6.0) * 0.25);
            let in_lower_bolt =
                fy >= 15.0 && fy <= 26.0 && fx >= (14.5 - (fy - 15.0) * 0.25) && fx <= (21.5 - (fy - 15.0) * 0.65);

            if in_upper_bolt || in_lower_bolt {
                px = bolt;
            }

            rgba[idx..idx + 4].copy_from_slice(&px);
        }
    }

    Icon::from_rgba(rgba, size as u32, size as u32).map_err(|e| format!("Icon RGBA: {}", e))
}
