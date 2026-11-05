//! Files built from every installed package: Info's `dir` index, icon, MIME,

use std::path::Path;

/// Whether `rel` (a path inside the union, e.g. `share/info/dir`) is such a file.
pub fn is_generated(rel: &Path) -> bool {
    let path = rel.to_string_lossy();
    let name = rel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let under = |dir: &str| path.starts_with(dir);

    path == "share/info/dir"
        || path == "share/applications/mimeinfo.cache"
        || path == "share/glib-2.0/schemas/gschemas.compiled"
        || (under("share/icons/") && name == "icon-theme.cache")
        || (under("share/mime/") && !under("share/mime/packages/"))
        || (under("lib/gio/modules/") && name == "giomodule.cache")
        || (under("lib/gdk-pixbuf-2.0/") && name == "loaders.cache")
        || ((under("lib/gtk-3.0/") || under("lib/gtk-4.0/")) && name == "immodules.cache")
        || (under("share/fonts/") && matches!(name.as_str(), "fonts.dir" | "fonts.scale" | ".uuid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_indexes_are_generated() {
        for p in [
            "share/info/dir",
            "share/icons/hicolor/icon-theme.cache",
            "share/applications/mimeinfo.cache",
            "share/glib-2.0/schemas/gschemas.compiled",
            "share/mime/mime.cache",
            "share/mime/text/x-nanorc.xml",
            "lib/gdk-pixbuf-2.0/2.10.0/loaders.cache",
            "share/fonts/misc/fonts.dir",
        ] {
            assert!(is_generated(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn package_files_are_kept() {
        for p in [
            "bin/nano",
            "share/info/nano.info",
            "share/mime/packages/nano.xml",
            "share/applications/nano.desktop",
            "share/icons/hicolor/48x48/apps/nano.png",
            "share/glib-2.0/schemas/org.example.gschema.xml",
        ] {
            assert!(!is_generated(Path::new(p)), "{p}");
        }
    }
}
