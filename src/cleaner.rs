//! Module de Nettoyage PC 100 % sûr avec aperçu préalable de l'espace récupérable.
//!
//! Catégories supportées :
//! 1. Fichiers temporaires utilisateur (`%TEMP%`)
//! 2. Fichiers temporaires Windows (`C:\Windows\Temp`)
//! 3. Cache Shaders GPU (NVIDIA DXCache/GLCache, AMD DxCache/GLCache, DirectX D3DSCache)
//! 4. Cache Windows Update (`C:\Windows\SoftwareDistribution\Download`, Admin requis)
//! 5. Corbeille Windows (`SHQueryRecycleBinW` / `SHEmptyRecycleBinW`)
//! 6. Fichiers `.log` et `.dmp` obsolètes (> 7 jours dans CrashDumps / Minidump / Windows\Logs)
//!
//! Garde-fous :
//! - Ne suit jamais les liens symboliques / jonctions NTFS (`!ft.is_symlink()`).
//! - Ignore silencieusement les fichiers verrouillés ou protégés sans erreur bloquante.
//! - N'efface jamais en dehors des dossiers temporaires/caches explicitement résolus.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, SystemTime};

use windows_sys::Win32::UI::Shell::{
    SHEmptyRecycleBinW, SHQueryRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI,
    SHERB_NOSOUND, SHQUERYRBINFO,
};

use crate::win32_ops;

/// Âge minimal des fichiers `.log`/`.dmp` pour être considérés obsolètes (7 jours).
const OBSOLETE_LOG_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CleanCategoryId {
    UserTemp,
    WindowsTemp,
    GpuShaderCache,
    WindowsUpdateCache,
    RecycleBin,
    ObsoleteLogsAndDumps,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanCategoryState {
    pub id: CleanCategoryId,
    pub title: String,
    pub subtitle: String,
    pub requires_admin: bool,
    pub selected: bool,
    pub scanned: bool,
    pub file_count: u64,
    pub bytes_recoverable: u64,
    pub paths_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanCategoryScan {
    pub id: CleanCategoryId,
    pub file_count: u64,
    pub bytes_recoverable: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanExecutionReport {
    pub files_deleted: u64,
    pub files_skipped_locked: u64,
    pub bytes_freed: u64,
    pub categories_cleaned: usize,
    pub details: Vec<String>,
}

/// Construit la liste initiale des 6 catégories de nettoyage avec sélection sûre par défaut.
pub fn default_clean_categories() -> Vec<CleanCategoryState> {
    vec![
        CleanCategoryState {
            id: CleanCategoryId::UserTemp,
            title: "Fichiers temporaires utilisateur".to_string(),
            subtitle: "Caches d'installation et fichiers temporaires de votre session (%TEMP%).".to_string(),
            requires_admin: false,
            selected: true,
            scanned: false,
            file_count: 0,
            bytes_recoverable: 0,
            paths_summary: r"%TEMP%".to_string(),
        },
        CleanCategoryState {
            id: CleanCategoryId::WindowsTemp,
            title: "Fichiers temporaires Windows".to_string(),
            subtitle: "Fichiers temporaires système (les fichiers en cours d'utilisation sont ignorés).".to_string(),
            requires_admin: true,
            selected: true,
            scanned: false,
            file_count: 0,
            bytes_recoverable: 0,
            paths_summary: r"C:\Windows\Temp".to_string(),
        },
        CleanCategoryState {
            id: CleanCategoryId::GpuShaderCache,
            title: "Cache Shaders GPU (NVIDIA / AMD / DirectX)".to_string(),
            subtitle: "Utile après une mise à jour de pilote graphique pour éliminer d'anciens shaders.".to_string(),
            requires_admin: false,
            selected: false,
            scanned: false,
            file_count: 0,
            bytes_recoverable: 0,
            paths_summary: "DXCache, GLCache, D3DSCache".to_string(),
        },
        CleanCategoryState {
            id: CleanCategoryId::WindowsUpdateCache,
            title: "Cache Windows Update".to_string(),
            subtitle: "Paquets de mises à jour déjà téléchargés dans SoftwareDistribution\\Download.".to_string(),
            requires_admin: true,
            selected: false,
            scanned: false,
            file_count: 0,
            bytes_recoverable: 0,
            paths_summary: r"C:\Windows\SoftwareDistribution\Download".to_string(),
        },
        CleanCategoryState {
            id: CleanCategoryId::RecycleBin,
            title: "Corbeille Windows".to_string(),
            subtitle: "Vide définitivement les éléments présents dans la Corbeille.".to_string(),
            requires_admin: false,
            selected: true,
            scanned: false,
            file_count: 0,
            bytes_recoverable: 0,
            paths_summary: "Corbeille système".to_string(),
        },
        CleanCategoryState {
            id: CleanCategoryId::ObsoleteLogsAndDumps,
            title: "Journaux (.log) et Crash Dumps (.dmp) obsolètes".to_string(),
            subtitle: "Anciens fichiers .log / .dmp de plus de 7 jours (CrashDumps, Minidump, Logs).".to_string(),
            requires_admin: false,
            selected: true,
            scanned: false,
            file_count: 0,
            bytes_recoverable: 0,
            paths_summary: "CrashDumps, Minidump, Windows\\Logs (> 7j)".to_string(),
        },
    ]
}

fn resolve_category_dirs(id: CleanCategoryId) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let local_app_data = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);

    match id {
        CleanCategoryId::UserTemp => {
            dirs.push(std::env::temp_dir());
        }
        CleanCategoryId::WindowsTemp => {
            dirs.push(PathBuf::from(r"C:\Windows\Temp"));
        }
        CleanCategoryId::GpuShaderCache => {
            if let Some(ref lad) = local_app_data {
                dirs.push(lad.join("NVIDIA").join("DXCache"));
                dirs.push(lad.join("NVIDIA").join("GLCache"));
                dirs.push(lad.join("D3DSCache"));
                dirs.push(lad.join("AMD").join("DxCache"));
                dirs.push(lad.join("AMD").join("GLCache"));
            }
        }
        CleanCategoryId::WindowsUpdateCache => {
            dirs.push(PathBuf::from(r"C:\Windows\SoftwareDistribution\Download"));
        }
        CleanCategoryId::RecycleBin => {}
        CleanCategoryId::ObsoleteLogsAndDumps => {
            if let Some(ref lad) = local_app_data {
                dirs.push(lad.join("CrashDumps"));
            }
            dirs.push(PathBuf::from(r"C:\Windows\Minidump"));
            dirs.push(PathBuf::from(r"C:\Windows\Logs"));
        }
    }

    dirs.into_iter().filter(|d| d.is_dir()).collect()
}

/// Vérifie si un fichier est un `.log` ou `.dmp` obsolète (> `max_age`).
pub fn is_obsolete_log_or_dump(path: &Path, metadata: &std::fs::Metadata, max_age: Duration) -> bool {
    let ext_match = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            ext.eq_ignore_ascii_case("log")
                || ext.eq_ignore_ascii_case("dmp")
                || ext.eq_ignore_ascii_case("mdmp")
        })
        .unwrap_or(false);
    if !ext_match {
        return false;
    }
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age >= max_age)
        .unwrap_or(false)
}

/// Interroge la taille et le nombre d'éléments de la Corbeille Windows via `SHQueryRecycleBinW`.
fn query_recycle_bin() -> (u64, u64) {
    unsafe {
        let mut info: SHQUERYRBINFO = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHQUERYRBINFO>() as u32;
        if SHQueryRecycleBinW(null(), &mut info) == 0 {
            let items = info.i64NumItems.max(0) as u64;
            let bytes = info.i64Size.max(0) as u64;
            (items, bytes)
        } else {
            (0, 0)
        }
    }
}

/// Scanne toutes les catégories sans rien supprimer et renvoie l'espace récupérable par catégorie.
pub fn scan_all_categories() -> Vec<CleanCategoryScan> {
    let ids = [
        CleanCategoryId::UserTemp,
        CleanCategoryId::WindowsTemp,
        CleanCategoryId::GpuShaderCache,
        CleanCategoryId::WindowsUpdateCache,
        CleanCategoryId::RecycleBin,
        CleanCategoryId::ObsoleteLogsAndDumps,
    ];

    ids.into_iter()
        .map(|id| match id {
            CleanCategoryId::RecycleBin => {
                let (files, bytes) = query_recycle_bin();
                CleanCategoryScan {
                    id,
                    file_count: files,
                    bytes_recoverable: bytes,
                }
            }
            CleanCategoryId::ObsoleteLogsAndDumps => {
                let dirs = resolve_category_dirs(id);
                let (files, bytes) = scan_dirs_recursive(&dirs, Some(OBSOLETE_LOG_AGE), 0);
                CleanCategoryScan {
                    id,
                    file_count: files,
                    bytes_recoverable: bytes,
                }
            }
            _ => {
                let dirs = resolve_category_dirs(id);
                let (files, bytes) = scan_dirs_recursive(&dirs, None, 0);
                CleanCategoryScan {
                    id,
                    file_count: files,
                    bytes_recoverable: bytes,
                }
            }
        })
        .collect()
}

fn scan_dirs_recursive(
    dirs: &[PathBuf],
    only_obsolete_logs: Option<Duration>,
    depth: usize,
) -> (u64, u64) {
    if depth > 8 {
        return (0, 0);
    }
    let mut files = 0u64;
    let mut bytes = 0u64;

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            // Sécurité absolue : ne jamais suivre de lien symbolique ou jonction NTFS
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                let (sub_f, sub_b) = scan_dirs_recursive(&[path], only_obsolete_logs, depth + 1);
                files += sub_f;
                bytes += sub_b;
            } else if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    if let Some(max_age) = only_obsolete_logs {
                        if !is_obsolete_log_or_dump(&path, &meta, max_age) {
                            continue;
                        }
                    }
                    files += 1;
                    bytes += meta.len();
                }
            }
        }
    }
    (files, bytes)
}

/// Exécute le nettoyage sûr des catégories sélectionnées.
/// Ignore proprement les fichiers verrouillés par Windows ou une application active.
pub fn execute_clean(selected_ids: &[CleanCategoryId]) -> CleanExecutionReport {
    let mut report = CleanExecutionReport::default();
    let is_admin = win32_ops::is_elevated();

    for &id in selected_ids {
        match id {
            CleanCategoryId::RecycleBin => {
                let (items, bytes) = query_recycle_bin();
                if items == 0 && bytes == 0 {
                    report
                        .details
                        .push("Corbeille : déjà vide.".to_string());
                    continue;
                }
                let hr = unsafe {
                    SHEmptyRecycleBinW(
                        null_mut(),
                        null(),
                        SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
                    )
                };
                if hr == 0 {
                    report.files_deleted += items;
                    report.bytes_freed += bytes;
                    report.categories_cleaned += 1;
                    report.details.push(format!(
                        "Corbeille vidée : {} élément(s), {} libérés.",
                        items,
                        format_bytes(bytes)
                    ));
                } else {
                    report.details.push(format!(
                        "Corbeille : aucun élément supprimé (code 0x{:08X}).",
                        hr
                    ));
                }
            }
            CleanCategoryId::WindowsUpdateCache if !is_admin => {
                report.details.push(
                    "Cache Windows Update ignoré : privilèges Administrateur requis.".to_string(),
                );
            }
            CleanCategoryId::ObsoleteLogsAndDumps => {
                let dirs = resolve_category_dirs(id);
                let (del, skip, freed) = clean_dirs_recursive(&dirs, Some(OBSOLETE_LOG_AGE), 0, false);
                report.files_deleted += del;
                report.files_skipped_locked += skip;
                report.bytes_freed += freed;
                report.categories_cleaned += 1;
                report.details.push(format!(
                    "Logs & Dumps obsolètes : {} supprimé(s), {} verrouillé(s), {} libérés.",
                    del,
                    skip,
                    format_bytes(freed)
                ));
            }
            _ => {
                let dirs = resolve_category_dirs(id);
                let (del, skip, freed) = clean_dirs_recursive(&dirs, None, 0, true);
                report.files_deleted += del;
                report.files_skipped_locked += skip;
                report.bytes_freed += freed;
                report.categories_cleaned += 1;
                let name = match id {
                    CleanCategoryId::UserTemp => "%TEMP%",
                    CleanCategoryId::WindowsTemp => r"C:\Windows\Temp",
                    CleanCategoryId::GpuShaderCache => "Cache Shaders GPU",
                    CleanCategoryId::WindowsUpdateCache => "Cache Windows Update",
                    _ => "Nettoyage",
                };
                report.details.push(format!(
                    "{} : {} fichier(s) supprimé(s), {} ignoré(s) (verrouillés), {} libérés.",
                    name,
                    del,
                    skip,
                    format_bytes(freed)
                ));
            }
        }
    }

    report
}

/// Supprime récursivement les fichiers dans `dirs` sans jamais supprimer les répertoires racines
/// ni traverser de liens symboliques. Retourne `(deleted, skipped_locked, bytes_freed)`.
pub fn clean_dirs_recursive(
    dirs: &[PathBuf],
    only_obsolete_logs: Option<Duration>,
    depth: usize,
    remove_empty_subdirs: bool,
) -> (u64, u64, u64) {
    if depth > 8 {
        return (0, 0, 0);
    }
    let mut deleted = 0u64;
    let mut skipped = 0u64;
    let mut freed = 0u64;

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                let (d, s, f) = clean_dirs_recursive(
                    &[path.clone()],
                    only_obsolete_logs,
                    depth + 1,
                    remove_empty_subdirs,
                );
                deleted += d;
                skipped += s;
                freed += f;
                if remove_empty_subdirs && only_obsolete_logs.is_none() {
                    let _ = std::fs::remove_dir(&path);
                }
            } else if ft.is_file() {
                let Ok(meta) = entry.metadata() else {
                    skipped += 1;
                    continue;
                };
                if let Some(max_age) = only_obsolete_logs {
                    if !is_obsolete_log_or_dump(&path, &meta, max_age) {
                        continue;
                    }
                }
                let size = meta.len();
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        deleted += 1;
                        freed += size;
                    }
                    Err(_) => {
                        // Fichier verrouillé ou accès refusé : ignoré proprement sans erreur bloquante
                        skipped += 1;
                    }
                }
            }
        }
    }
    (deleted, skipped, freed)
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} Go", b / GB)
    } else if b >= MB {
        format!("{:.1} Mo", b / MB)
    } else if b >= KB {
        format!("{:.0} Ko", b / KB)
    } else {
        format!("{} o", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn test_clean_dir_removes_temp_files_and_skips_locked_gracefully() {
        let base = std::env::temp_dir().join(format!("winboost_cleaner_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let normal_file = base.join("junk.tmp");
        let mut f1 = File::create(&normal_file).unwrap();
        f1.write_all(&vec![0x41u8; 4096]).unwrap();
        drop(f1);

        // Fichier verrouillé exclusivement (share_mode = 0) pour simuler un fichier en cours d'usage
        let locked_path = base.join("in_use.lock");
        let _locked_handle = OpenOptions::new()
            .create(true)
            .write(true)
            .share_mode(0)
            .open(&locked_path)
            .unwrap();

        let (scan_files, scan_bytes) = scan_dirs_recursive(&[base.clone()], None, 0);
        assert_eq!(scan_files, 2);
        assert!(scan_bytes >= 4096);

        let (deleted, skipped, freed) = clean_dirs_recursive(&[base.clone()], None, 0, true);
        assert_eq!(deleted, 1);
        assert_eq!(skipped, 1);
        assert_eq!(freed, 4096);
        assert!(!normal_file.exists());
        assert!(locked_path.exists());

        drop(_locked_handle);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_obsolete_log_filter_protects_recent_logs_and_non_log_files() {
        let base = std::env::temp_dir().join(format!("winboost_logfilter_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let recent_log = base.join("active.log");
        File::create(&recent_log).unwrap();
        let meta_log = std::fs::metadata(&recent_log).unwrap();
        // Un log tout juste créé ne doit PAS être supprimé avec un seuil de 7 jours
        assert!(!is_obsolete_log_or_dump(&recent_log, &meta_log, OBSOLETE_LOG_AGE));
        // Avec un seuil de 0s, un .log est éligible mais un .txt ne l'est pas
        assert!(is_obsolete_log_or_dump(&recent_log, &meta_log, Duration::ZERO));

        let non_log = base.join("important.txt");
        File::create(&non_log).unwrap();
        let meta_txt = std::fs::metadata(&non_log).unwrap();
        assert!(!is_obsolete_log_or_dump(&non_log, &meta_txt, Duration::ZERO));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_format_bytes_human_readable() {
        assert_eq!(format_bytes(512), "512 o");
        assert_eq!(format_bytes(2048), "2 Ko");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 Mo");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 Go");
    }
}
