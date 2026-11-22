//! Bibliothèque cœur partagée entre `winboost-svc` (daemon/service ultra-léger)
//! et `winboost-ui` (interface native Win32 / Direct2D / DirectWrite).

pub mod cleaner;
pub mod engine;
pub mod ipc;
pub mod models;
pub mod monitoring;
pub mod recovery;
pub mod self_test;
pub mod tray;
pub mod ui;
pub mod whitelist;
pub mod win32_ops;
