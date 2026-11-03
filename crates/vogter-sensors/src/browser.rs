//! Browser extensions installed for the watched user: Chromium browsers
//! (Chrome, Brave, Edge, Arc, Vivaldi, Chromium, Opera), Firefox and Safari.
//!
//! Read only: we parse the browsers' own records (`Preferences`,
//! `extensions.json`, `pluginkit`) and each extension's `manifest.json`.
//! Recent macOS versions protect other apps' data folders, so this needs
//! Full Disk Access like the permission databases do.

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use vogter_model::{BrowserExtension, ExtensionSource, SignatureKind};

use crate::codesign;

/// Source label for Safari findings (they have no profile folder of their own).
pub const SAFARI_SOURCE: &str = "safari";

/// Chromium browsers: (name, folder under `~/Library/Application Support`).
const CHROMIUM: &[(&str, &str)] = &[
    ("Google Chrome", "Google/Chrome"),
    ("Google Chrome Beta", "Google/Chrome Beta"),
    ("Google Chrome Canary", "Google/Chrome Canary"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Microsoft Edge", "Microsoft Edge"),
    ("Arc", "Arc/User Data"),
    ("Vivaldi", "Vivaldi"),
    ("Chromium", "Chromium"),
    ("Opera", "com.operasoftware.Opera"),
];

/// Errors are `(source, message)`: the browser or profile folder that couldn't be read.
pub fn collect(errors: &mut Vec<(String, String)>) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    if let Some(user) = crate::user::target() {
        let support = Path::new(&user.home).join("Library/Application Support");
        for (browser, dir) in CHROMIUM {
            chromium_browser(browser, &support.join(dir), &mut out, errors);
        }
        firefox(&support.join("Firefox/Profiles"), &mut out, errors);
    }
    match safari() {
        Ok(mut s) => out.append(&mut s),
        Err(e) => errors.push((SAFARI_SOURCE.into(), e)),
    }
    out.sort_by(|a, b| {
        (&a.browser, &a.profile, &a.name, &a.id).cmp(&(&b.browser, &b.profile, &b.name, &b.id))
    });
    out
}

fn unreadable(path: &Path, e: impl std::fmt::Display) -> (String, String) {
    unreadable_in(path, path, e)
}

/// `source` is the folder whose findings become unknown; `path` what failed.
fn unreadable_in(source: &Path, path: &Path, e: impl std::fmt::Display) -> (String, String) {
    (
        source.display().to_string(),
        format!(
            "{}: {e} ({})",
            path.display(),
            crate::tcc::full_disk_access_hint()
        ),
    )
}

fn read_json(path: &Path) -> std::io::Result<Value> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Chromium
// ---------------------------------------------------------------------------

fn chromium_browser(
    browser: &str,
    base: &Path,
    out: &mut Vec<BrowserExtension>,
    errors: &mut Vec<(String, String)>,
) {
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return, // not installed
        Err(e) => return errors.push(unreadable(base, e)),
    };
    // Profile display names ("Work", "Personal") live in `Local State`.
    let names: BTreeMap<String, String> = read_json(&base.join("Local State"))
        .ok()
        .and_then(|v| v.pointer("/profile/info_cache").cloned())
        .and_then(|v| v.as_object().cloned())
        .map(|m| {
            m.into_iter()
                .filter_map(|(dir, info)| Some((dir, info.get("name")?.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut profiles: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            (name == "Default" || name.starts_with("Profile ")) && p.is_dir()
        })
        .collect();
    // Opera keeps its one profile in the browser folder itself.
    if base.join("Preferences").exists() {
        profiles.push(base.to_path_buf());
    }
    profiles.sort();
    for dir in profiles {
        let folder = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let label = names.get(&folder).cloned().unwrap_or(if dir == base {
            "Default".into()
        } else {
            folder
        });
        match chromium_profile(browser, &label, &dir) {
            Ok(mut exts) => out.append(&mut exts),
            Err(e) => errors.push(e),
        }
    }
}

/// One profile: the extension records in `Preferences` and `Secure Preferences`,
/// plus each extension's manifest on disk.
pub fn chromium_profile(
    browser: &str,
    profile: &str,
    dir: &Path,
) -> Result<Vec<BrowserExtension>, (String, String)> {
    let mut settings = serde_json::Map::new();
    let mut read_any = false;
    for file in ["Preferences", "Secure Preferences"] {
        let path = dir.join(file);
        match read_json(&path) {
            Ok(v) => {
                read_any = true;
                if let Some(s) = v.pointer("/extensions/settings").and_then(Value::as_object) {
                    for (id, rec) in s {
                        merge(settings.entry(id.clone()).or_insert(Value::Null), rec);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(unreadable_in(dir, &path, e)),
        }
    }
    let ext_dir = dir.join("Extensions");
    // Folders on disk that Preferences doesn't mention (not loaded by the browser).
    let mut on_disk: BTreeSet<String> = match std::fs::read_dir(&ext_dir) {
        Ok(e) => e
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_lowercase()))
            .collect(),
        Err(e) if e.kind() == ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(unreadable_in(dir, &ext_dir, e)),
    };
    if !read_any && on_disk.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for (id, rec) in &settings {
        on_disk.remove(id);
        if let Some(ext) = chromium_extension(browser, profile, dir, id, Some(rec)) {
            out.push(ext);
        }
    }
    for id in on_disk {
        if let Some(ext) = chromium_extension(browser, profile, dir, &id, None) {
            out.push(ext);
        }
    }
    Ok(out)
}

/// Deep-merge `src` into `dst` (objects key by key, anything else replaced).
fn merge(dst: &mut Value, src: &Value) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                merge(d.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (d, s) => *d = s.clone(),
    }
}

/// Chromium's `ManifestLocation`.
fn chromium_source(location: i64, from_store: bool, by_default: bool) -> Option<ExtensionSource> {
    Some(match location {
        // Component extensions are part of the browser itself.
        5 | 10 => return None,
        _ if by_default => ExtensionSource::Preinstalled,
        1 if from_store => ExtensionSource::Store,
        // kInternal from a .crx file; kExternalPref/Registry/PrefDownload: put
        // there by another program (adware's favourite way in).
        1 | 2 | 3 | 6 => ExtensionSource::Sideloaded,
        4 | 8 => ExtensionSource::Developer,
        7 | 9 => ExtensionSource::Policy,
        _ => ExtensionSource::Unknown,
    })
}

pub fn chromium_extension(
    browser: &str,
    profile: &str,
    profile_dir: &Path,
    id: &str,
    rec: Option<&Value>,
) -> Option<BrowserExtension> {
    let int = |k: &str| rec.and_then(|r| r.get(k)).and_then(Value::as_i64);
    let flag = |k: &str| {
        rec.and_then(|r| r.get(k))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let source = match rec {
        Some(_) => chromium_source(
            int("location").unwrap_or(0),
            flag("from_webstore"),
            flag("was_installed_by_default") || flag("was_installed_by_oem"),
        )?,
        None => ExtensionSource::Unknown,
    };

    // Where it lives: `path` is relative to Extensions/ for installed ones and
    // absolute for unpacked ones.
    let rec_path = rec.and_then(|r| r.get("path")).and_then(Value::as_str);
    let ext_root = profile_dir.join("Extensions").join(id);
    let version_dir = match rec_path {
        Some(p) if p.starts_with('/') => Some(PathBuf::from(p)),
        Some(p) if !p.is_empty() => Some(profile_dir.join("Extensions").join(p)),
        _ => None,
    }
    .filter(|d| d.join("manifest.json").exists())
    .or_else(|| latest_version_dir(&ext_root));
    let manifest = version_dir
        .as_ref()
        .and_then(|d| read_json(&d.join("manifest.json")).ok())
        .or_else(|| rec.and_then(|r| r.get("manifest")).cloned());
    if rec.is_none() && manifest.is_none() {
        return None;
    }
    let manifest = manifest.unwrap_or(Value::Null);
    // Themes only change colours.
    if manifest.get("theme").is_some() {
        return None;
    }

    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .map(|n| localize(n, &manifest, version_dir.as_deref()))
        .unwrap_or_else(|| id.to_string());
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let (mut permissions, mut hosts) = manifest_permissions(&manifest);
    for key in ["granted_permissions", "active_permissions"] {
        if let Some(g) = rec.and_then(|r| r.get(key)) {
            for p in strings(g.get("api")) {
                add(&mut permissions, &mut hosts, p);
            }
            for k in ["explicit_host", "scriptable_host"] {
                hosts.extend(strings(g.get(k)));
            }
        }
    }

    // Older Chromium: state 1/0. Newer: only disable_reasons (an int or a list).
    let disabled_reasons = match rec.and_then(|r| r.get("disable_reasons")) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        Some(Value::Array(a)) => !a.is_empty(),
        _ => false,
    };
    let enabled = rec.is_some()
        && match int("state") {
            Some(s) => s == 1 && !disabled_reasons,
            None => !disabled_reasons,
        };

    let install_time = rec
        .and_then(|r| {
            r.get("first_install_time")
                .or_else(|| r.get("install_time"))
        })
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(webkit_to_unix);

    let path = match rec_path {
        Some(p) if p.starts_with('/') => Some(p.to_string()),
        _ if ext_root.exists() => Some(ext_root.display().to_string()),
        _ => version_dir.map(|d| d.display().to_string()),
    };

    Some(BrowserExtension {
        browser: browser.into(),
        profile: profile.into(),
        profile_path: profile_dir.display().to_string(),
        id: id.into(),
        name,
        version,
        enabled,
        source,
        permissions: permissions.into_iter().collect(),
        host_permissions: hosts.into_iter().collect(),
        path,
        install_time,
        signing: None,
    })
}

/// The newest `<id>/<version>` folder that has a manifest.
fn latest_version_dir(root: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("manifest.json").exists())
        .collect();
    dirs.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    dirs.pop()
}

/// Microseconds since 1601 (Chromium's clock) to Unix seconds.
fn webkit_to_unix(us: u64) -> Option<u64> {
    (us / 1_000_000).checked_sub(11_644_473_600)
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| match x {
                    Value::String(s) => Some(s.clone()),
                    // `{"fileSystem": [...]}`-style entries: the key is the permission.
                    Value::Object(o) => o.keys().next().cloned(),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn is_host_pattern(p: &str) -> bool {
    p == "<all_urls>" || p.contains("://")
}

fn add(perms: &mut BTreeSet<String>, hosts: &mut BTreeSet<String>, p: String) {
    if is_host_pattern(&p) {
        hosts.insert(p);
    } else {
        perms.insert(p);
    }
}

/// API permissions and the sites it can touch, from a WebExtension manifest
/// (Chromium, Firefox and Safari share the format). Optional permissions are
/// left out: they need a separate prompt.
pub fn manifest_permissions(m: &Value) -> (BTreeSet<String>, BTreeSet<String>) {
    let (mut perms, mut hosts) = (BTreeSet::new(), BTreeSet::new());
    for p in strings(m.get("permissions")) {
        add(&mut perms, &mut hosts, p);
    }
    hosts.extend(strings(m.get("host_permissions")));
    // Content scripts run inside the matching pages, which is the same power.
    if let Some(cs) = m.get("content_scripts").and_then(Value::as_array) {
        for s in cs {
            hosts.extend(strings(s.get("matches")));
        }
    }
    (perms, hosts)
}

/// Resolve `__MSG_name__` from `_locales/<default_locale>/messages.json`.
fn localize(name: &str, manifest: &Value, dir: Option<&Path>) -> String {
    let Some(key) = name
        .strip_prefix("__MSG_")
        .and_then(|k| k.strip_suffix("__"))
    else {
        return name.to_string();
    };
    let Some(dir) = dir else {
        return name.to_string();
    };
    let default = manifest
        .get("default_locale")
        .and_then(Value::as_str)
        .unwrap_or("en");
    for locale in [default, "en", "en_US", "en_GB"] {
        let Ok(msgs) = read_json(&dir.join("_locales").join(locale).join("messages.json")) else {
            continue;
        };
        // Message keys are case-insensitive.
        let hit = msgs.as_object().and_then(|o| {
            o.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .and_then(|(_, v)| v.get("message")?.as_str())
        });
        if let Some(m) = hit {
            return m.to_string();
        }
    }
    name.to_string()
}

// ---------------------------------------------------------------------------
// Firefox
// ---------------------------------------------------------------------------

fn firefox(profiles: &Path, out: &mut Vec<BrowserExtension>, errors: &mut Vec<(String, String)>) {
    let entries = match std::fs::read_dir(profiles) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return,
        Err(e) => return errors.push(unreadable(profiles, e)),
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let path = dir.join("extensions.json");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => {
                errors.push(unreadable_in(&dir, &path, e));
                continue;
            }
        };
        // "abcd1234.default-release" -> "default-release"
        let folder = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let profile = folder
            .split_once('.')
            .map(|(_, n)| n.to_string())
            .unwrap_or(folder);
        match firefox_extensions(&text, &profile, &dir) {
            Ok(mut e) => out.append(&mut e),
            Err(e) => errors.push(unreadable_in(&dir, &path, e)),
        }
    }
}

/// Parse one profile's `extensions.json`.
pub fn firefox_extensions(
    text: &str,
    profile: &str,
    dir: &Path,
) -> Result<Vec<BrowserExtension>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let addons = v
        .get("addons")
        .and_then(Value::as_array)
        .ok_or("no addons list")?;
    let mut out = Vec::new();
    for a in addons {
        let s = |k: &str| a.get(k).and_then(Value::as_str);
        let b = |k: &str| a.get(k).and_then(Value::as_bool).unwrap_or(false);
        let location = s("location").unwrap_or("");
        // Built into Firefox or shipped as system add-ons.
        if s("type") != Some("extension")
            || b("isSystem")
            || b("isBuiltin")
            || matches!(
                location,
                "app-builtin" | "app-system-defaults" | "app-system-addons"
            )
        {
            continue;
        }
        let install = a
            .pointer("/installTelemetryInfo/source")
            .and_then(Value::as_str)
            .unwrap_or("");
        let source_uri = s("sourceURI").unwrap_or("");
        let source = if install == "enterprise-policy" {
            ExtensionSource::Policy
        } else if install == "temporary-addon" || location == "app-temporary" {
            ExtensionSource::Developer
        } else if install == "distribution" {
            ExtensionSource::Preinstalled
        } else if matches!(install, "amo" | "disco" | "about:addons" | "rtamo" | "sync")
            || source_uri.starts_with("https://addons.mozilla.org/")
        {
            ExtensionSource::Store
        } else if location == "app-profile" && install.is_empty() && source_uri.is_empty() {
            // Older installs carry no telemetry; Mozilla's signature is the best hint.
            if a.get("signedState").and_then(Value::as_i64).unwrap_or(0) >= 2 {
                ExtensionSource::Store
            } else {
                ExtensionSource::Unknown
            }
        } else {
            // file-url, or dropped in a global/system folder by another program.
            ExtensionSource::Sideloaded
        };
        let perms = strings(a.pointer("/userPermissions/permissions"));
        let mut hosts = strings(a.pointer("/userPermissions/origins"));
        // Content scripts are listed separately from origins in newer versions.
        if let Some(cs) = a.get("contentScripts").and_then(Value::as_array) {
            for c in cs {
                hosts.extend(strings(c.get("matches")));
            }
        }
        hosts.sort();
        hosts.dedup();
        let id = s("id").unwrap_or("").to_string();
        out.push(BrowserExtension {
            browser: "Firefox".into(),
            profile: profile.into(),
            profile_path: dir.display().to_string(),
            name: a
                .pointer("/defaultLocale/name")
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_string(),
            id,
            version: s("version").unwrap_or("").to_string(),
            enabled: b("active") && !b("userDisabled") && !b("appDisabled"),
            source,
            permissions: perms,
            host_permissions: hosts,
            path: s("path").map(str::to_string),
            install_time: a
                .get("installDate")
                .and_then(Value::as_u64)
                .map(|ms| ms / 1000),
            signing: None,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Safari
// ---------------------------------------------------------------------------

/// Safari extensions are app extensions, registered with pluginkit.
fn safari() -> Result<Vec<BrowserExtension>, String> {
    let mut out = Vec::new();
    for sdk in [
        "com.apple.Safari.web-extension",
        "com.apple.Safari.extension",
    ] {
        let text = pluginkit(sdk)?;
        for p in parse_pluginkit(&text) {
            let manifest = read_json(&Path::new(&p.path).join("Contents/Resources/manifest.json"))
                .unwrap_or(Value::Null);
            let (perms, hosts) = manifest_permissions(&manifest);
            let signing = p.parent.as_deref().map(codesign::for_path);
            let source = match &signing {
                Some(s) if s.is_weak() => ExtensionSource::Developer,
                Some(s) if s.kind == SignatureKind::Unknown => ExtensionSource::Unknown,
                _ => ExtensionSource::Store,
            };
            out.push(BrowserExtension {
                browser: "Safari".into(),
                profile: p.parent_name.clone().unwrap_or_default(),
                profile_path: SAFARI_SOURCE.into(),
                id: p.id,
                name: p.name,
                version: p.version,
                enabled: p.enabled,
                source,
                permissions: perms.into_iter().collect(),
                host_permissions: hosts.into_iter().collect(),
                path: p.parent.or(Some(p.path)),
                install_time: None,
                signing,
            });
        }
    }
    Ok(out)
}

fn pluginkit(sdk: &str) -> Result<String, String> {
    let args = ["-mAvvv", "-p", sdk];
    // As root, ask in the console user's session: plug-ins are registered per user.
    let mut cmd = match crate::user::target().filter(|_| crate::user::is_root()) {
        Some(u) => {
            let mut c = Command::new("/bin/launchctl");
            c.args(["asuser", &u.uid.to_string(), "/usr/bin/sudo", "-u", &u.name])
                .arg("/usr/bin/pluginkit");
            c
        }
        None => Command::new("/usr/bin/pluginkit"),
    };
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("pluginkit: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "pluginkit: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Debug, PartialEq)]
pub struct Plugin {
    pub id: String,
    pub version: String,
    pub path: String,
    pub parent: Option<String>,
    pub parent_name: Option<String>,
    pub name: String,
    /// `-` in the first column: the user turned it off.
    pub enabled: bool,
}

pub fn parse_pluginkit(text: &str) -> Vec<Plugin> {
    let mut out: Vec<Plugin> = Vec::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(" = ") {
            let Some(p) = out.last_mut() else { continue };
            let v = v.trim().to_string();
            match k.trim() {
                "Path" => p.path = v,
                "Parent Bundle" => p.parent = Some(v),
                "Parent Name" => p.parent_name = Some(v),
                "Display Name" => p.name = v,
                _ => {}
            }
            continue;
        }
        let flag = line.chars().next().unwrap_or(' ');
        let head = line.trim_start_matches(['+', '-', '!', '=', '?']).trim();
        let Some((id, rest)) = head.split_once('(') else {
            continue;
        };
        if id.contains(' ') || id.is_empty() {
            continue; // "(1 plug-in)", "(no matches)"
        }
        out.push(Plugin {
            id: id.to_string(),
            version: rest.trim_end_matches(')').to_string(),
            path: String::new(),
            parent: None,
            parent_name: None,
            name: id.to_string(),
            enabled: flag != '-',
        });
    }
    out.retain(|p| !p.path.is_empty());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vogter-browser-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    const STORE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DEV_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const COMPONENT_ID: &str = "cccccccccccccccccccccccccccccccc";

    #[test]
    fn chromium_profile_from_fixtures() {
        let dir = tmp("chromium");
        let unpacked = dir.join("dev-ext");
        write(
            &dir.join(format!("Extensions/{STORE_ID}/1.2_0/manifest.json")),
            r#"{"name":"__MSG_appName__","version":"1.2","default_locale":"de",
                "manifest_version":3,"permissions":["storage","cookies"],
                "host_permissions":["<all_urls>"]}"#,
        );
        write(
            &dir.join(format!(
                "Extensions/{STORE_ID}/1.2_0/_locales/de/messages.json"
            )),
            r#"{"APPNAME":{"message":"Kekse"}}"#,
        );
        write(
            &unpacked.join("manifest.json"),
            r#"{"name":"My Dev","version":"0.1","permissions":["tabs","https://*/*"],
                "content_scripts":[{"matches":["*://*.example.com/*"],"js":["a.js"]}]}"#,
        );
        let unpacked_str = unpacked.display().to_string();
        write(
            &dir.join("Preferences"),
            &format!(
                r#"{{"extensions":{{"settings":{{
                "{STORE_ID}":{{"location":1,"from_webstore":true,"state":1,"path":"{STORE_ID}/1.2_0",
                   "install_time":"13300000000000000"}},
                "{COMPONENT_ID}":{{"location":5,"state":1}}
            }}}}}}"#
            ),
        );
        write(
            &dir.join("Secure Preferences"),
            &format!(
                r#"{{"extensions":{{"settings":{{
                "{DEV_ID}":{{"location":4,"path":"{unpacked_str}","disable_reasons":[]}},
                "{STORE_ID}":{{"granted_permissions":{{"api":["cookies","alarms"],"explicit_host":["<all_urls>"]}}}}
            }}}}}}"#
            ),
        );

        let exts = chromium_profile("Brave", "Default", &dir).unwrap();
        assert_eq!(exts.len(), 2, "{exts:#?}");
        let store = exts.iter().find(|e| e.id == STORE_ID).unwrap();
        assert_eq!(store.name, "Kekse");
        assert_eq!(store.version, "1.2");
        assert_eq!(store.source, ExtensionSource::Store);
        assert!(store.enabled);
        assert_eq!(store.permissions, ["alarms", "cookies", "storage"]);
        assert_eq!(store.host_permissions, ["<all_urls>"]);
        assert_eq!(
            store.path.as_deref(),
            Some(dir.join("Extensions").join(STORE_ID).to_str().unwrap())
        );
        assert_eq!(store.install_time, Some(1_655_526_400));

        let dev = exts.iter().find(|e| e.id == DEV_ID).unwrap();
        assert_eq!(dev.name, "My Dev");
        assert_eq!(dev.source, ExtensionSource::Developer);
        assert!(dev.enabled);
        assert_eq!(dev.permissions, ["tabs"]);
        assert_eq!(dev.host_permissions, ["*://*.example.com/*", "https://*/*"]);
        assert_eq!(dev.path.as_deref(), Some(unpacked_str.as_str()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unreadable_preferences_is_an_error_for_that_profile() {
        let dir = tmp("broken");
        write(&dir.join("Preferences"), "{not json");
        let (src, _) = chromium_profile("Google Chrome", "Default", &dir).unwrap_err();
        assert_eq!(src, dir.display().to_string());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn chromium_locations() {
        use ExtensionSource::*;
        assert_eq!(chromium_source(1, true, false), Some(Store));
        assert_eq!(chromium_source(1, false, false), Some(Sideloaded));
        assert_eq!(chromium_source(6, false, false), Some(Sideloaded));
        assert_eq!(chromium_source(4, false, false), Some(Developer));
        assert_eq!(chromium_source(9, false, false), Some(Policy));
        assert_eq!(chromium_source(6, true, true), Some(Preinstalled));
        assert_eq!(chromium_source(5, false, false), None);
    }

    #[test]
    fn firefox_sample() {
        let json = r#"{"schemaVersion":36,"addons":[
          {"id":"uBlock0@raymondhill.net","type":"extension","version":"1.60.0",
           "location":"app-profile","active":true,"userDisabled":false,"signedState":2,
           "sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/ublock.xpi",
           "installTelemetryInfo":{"source":"amo"},
           "defaultLocale":{"name":"uBlock Origin"},
           "path":"/p/extensions/uBlock0@raymondhill.net.xpi",
           "userPermissions":{"permissions":["dns","webRequest","webRequestBlocking"],"origins":["<all_urls>"]}},
          {"id":"helper@corp","type":"extension","version":"2","location":"app-profile",
           "active":true,"installTelemetryInfo":{"source":"enterprise-policy"},
           "defaultLocale":{"name":"Corp Helper"},"userPermissions":{"permissions":[],"origins":[]}},
          {"id":"evil@x","type":"extension","version":"1","location":"app-global","active":false,
           "userDisabled":true,"installTelemetryInfo":{"source":"file-url"},"defaultLocale":{"name":"Evil"}},
          {"id":"screenshots@mozilla.org","type":"extension","location":"app-builtin","isBuiltin":true},
          {"id":"default-theme@mozilla.org","type":"theme","location":"app-builtin"}
        ]}"#;
        let exts = firefox_extensions(json, "default-release", Path::new("/p")).unwrap();
        assert_eq!(exts.len(), 3);
        assert_eq!(exts[0].name, "uBlock Origin");
        assert_eq!(exts[0].source, ExtensionSource::Store);
        assert_eq!(exts[0].host_permissions, ["<all_urls>"]);
        assert!(exts[0].enabled);
        assert_eq!(exts[1].source, ExtensionSource::Policy);
        assert_eq!(exts[2].source, ExtensionSource::Sideloaded);
        assert!(!exts[2].enabled);
    }

    #[test]
    fn pluginkit_output() {
        let text = "     com.agilebits.onepassword7.1PasswordSafariAppExtension(7.9.11)\n\
            \t            Path = /Applications/1Password 7.app/Contents/PlugIns/1P.appex\n\
            \t            UUID = AFA86E99\n\
            \t   Parent Bundle = /Applications/1Password 7.app\n\
            \t    Display Name = 1Password\n\
            \t     Parent Name = 1Password 7\n\
            -    com.example.off(1.0)\n\
            \t            Path = /Applications/Off.app/Contents/PlugIns/Off.appex\n\
            \n (2 plug-ins)\n";
        let p = parse_pluginkit(text);
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[0].id,
            "com.agilebits.onepassword7.1PasswordSafariAppExtension"
        );
        assert_eq!(p[0].version, "7.9.11");
        assert_eq!(p[0].name, "1Password");
        assert_eq!(
            p[0].parent.as_deref(),
            Some("/Applications/1Password 7.app")
        );
        assert!(p[0].enabled);
        assert!(!p[1].enabled);
        assert!(parse_pluginkit("  (no matches)\n").is_empty());
    }
}
