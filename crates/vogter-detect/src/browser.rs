//! Browser extensions: what's installed, and which ones could spy on you.
//!
//! One finding per extension. Extensions that can read every website and use
//! powerful APIs (cookies, web traffic...) are how sessions get stolen and
//! wallets drained, but password managers and ad blockers legitimately need
//! the same access, so these are Medium and the text says when that's normal.
//! Extensions that didn't come from a store are High.

use vogter_model::{BrowserExtension, Category, ExtensionSource, Finding, Severity};

/// API permissions that turn "can see every website" into real power, with what they allow.
const POWERFUL: &[(&str, &str)] = &[
    (
        "cookies",
        "read your login cookies (enough to take over signed-in accounts)",
    ),
    ("webRequest", "watch your web traffic"),
    ("webRequestBlocking", "change your web traffic"),
    ("declarativeNetRequest", "block or redirect web requests"),
    (
        "declarativeNetRequestWithHostAccess",
        "block or redirect web requests",
    ),
    (
        "debugger",
        "take full control of pages through the debugger",
    ),
    ("nativeMessaging", "talk to a program installed on your Mac"),
    ("proxy", "send all your browsing through a server it picks"),
    ("history", "read your browsing history"),
    ("clipboardRead", "read your clipboard"),
    ("scripting", "run its own code inside pages"),
    ("tabs", "see the address and title of every tab"),
    ("management", "turn other extensions on and off"),
    ("privacy", "change the browser's privacy settings"),
    ("downloads", "download and open files"),
];

pub fn assess(exts: &[BrowserExtension]) -> Vec<Finding> {
    exts.iter().map(extension).collect()
}

/// `<all_urls>`, `*://*/*`, `https://*/*`...: a pattern whose host is any site.
pub fn is_all_sites(pattern: &str) -> bool {
    if pattern == "<all_urls>" {
        return true;
    }
    let Some((scheme, rest)) = pattern.split_once("://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    matches!(scheme, "*" | "http" | "https") && host == "*"
}

/// Where to remove or turn off extensions in this browser.
fn settings_page(browser: &str) -> &'static str {
    match browser {
        "Brave" => "brave://extensions",
        "Microsoft Edge" => "edge://extensions",
        "Vivaldi" => "vivaldi://extensions",
        "Opera" => "opera://extensions",
        "Arc" => "arc://extensions",
        "Firefox" => "about:addons",
        "Safari" => "Safari → Settings → Extensions",
        _ => "chrome://extensions",
    }
}

fn extension(e: &BrowserExtension) -> Finding {
    let all_sites = e.host_permissions.iter().any(|h| is_all_sites(h));
    let powers: Vec<&str> = POWERFUL
        .iter()
        .filter(|(p, _)| e.permissions.iter().any(|q| q == p))
        .map(|(_, what)| *what)
        .collect();
    let native = e.permissions.iter().any(|p| p == "nativeMessaging");
    let page = settings_page(&e.browser);
    let who = if e.profile.is_empty() || e.profile == "Default" {
        e.browser.clone()
    } else {
        format!("{} ({})", e.browser, e.profile)
    };

    let version = if e.version.is_empty() {
        String::new()
    } else {
        format!(" {}", e.version)
    };
    let mut detail = format!("{}{version} in {who}.", e.name);
    // Safari asks you per website before an extension can read it.
    let safari = e.browser == "Safari";
    if all_sites && !safari {
        detail.push_str(" It can read and change everything on every website you visit");
        if powers.is_empty() {
            detail.push('.');
        } else {
            detail.push_str(&format!(", and {}.", join(&powers)));
        }
    } else if !powers.is_empty() {
        detail.push_str(&format!(" It can {}.", join(&powers)));
    }
    if safari && all_sites {
        detail.push_str(" It asks for access to all websites; Safari lets you allow it per site.");
    }
    if native {
        detail.push_str(
            " With nativeMessaging it can talk to a program on your Mac, so it can reach \
             outside the browser: normal for password managers and download helpers.",
        );
    }

    let (severity, check, title) = if !e.enabled {
        detail.push_str(" It is turned off.");
        (
            Severity::Info,
            "browser.extension.installed",
            format!("{} in {} (turned off)", e.name, e.browser),
        )
    } else {
        match e.source {
            ExtensionSource::Developer => {
                detail.push_str(&format!(
                    " It is loaded from a folder in developer mode, not installed from a store, \
                     so nobody reviewed it and it can change at any time. Fine if you're \
                     building it yourself; otherwise remove it in {page} and turn developer \
                     mode off."
                ));
                (
                    Severity::High,
                    "browser.extension.developer",
                    format!("{} in {} is a developer-mode extension", e.name, e.browser),
                )
            }
            ExtensionSource::Sideloaded => {
                detail.push_str(&format!(
                    " It wasn't installed from the browser's store: it came from a file or was \
                     put there by another program, which is how adware and data-stealing \
                     extensions usually arrive. If you don't recognise it, remove it in {page} \
                     and check Applications for whatever installed it."
                ));
                (
                    Severity::High,
                    "browser.extension.sideloaded",
                    format!("{} in {} wasn't installed from a store", e.name, e.browser),
                )
            }
            ExtensionSource::Policy => {
                detail.push_str(&format!(
                    " It was installed by a management policy, so you can't remove it in \
                     {page}. Normal on a work or school Mac (your employer's device \
                     management). On a personal Mac, look for a profile you don't recognise \
                     in System Settings → General → Device Management."
                ));
                (
                    Severity::Medium,
                    "browser.extension.policy",
                    format!("{} in {} was installed by a policy", e.name, e.browser),
                )
            }
            _ if all_sites && !powers.is_empty() && !safari => {
                detail.push_str(&format!(
                    " Password managers, ad blockers and translators legitimately need this. \
                     If you don't use it or don't recognise it, remove it in {page}."
                ));
                (
                    Severity::Medium,
                    "browser.extension.all_sites",
                    format!(
                        "{} in {} can read and change all your data on all websites",
                        e.name, e.browser
                    ),
                )
            }
            ref s => {
                if *s == ExtensionSource::Unknown {
                    detail.push_str(" Vogter couldn't tell where it was installed from.");
                }
                (
                    Severity::Info,
                    "browser.extension.installed",
                    format!("{} in {}", e.name, e.browser),
                )
            }
        }
    };
    if !e.permissions.is_empty() {
        detail.push_str(&format!(" Permissions: {}.", e.permissions.join(", ")));
    }
    if !e.host_permissions.is_empty() {
        detail.push_str(&format!(" Sites: {}.", sites(&e.host_permissions)));
    }
    detail.push_str(&format!(" ID {}.", e.id));

    Finding {
        severity,
        category: Category::Browser,
        check: check.into(),
        title,
        detail,
        pid: None,
        path: e.path.clone(),
        signing: e.signing.clone(),
        source: Some(e.profile_path.clone()),
    }
}

/// "a", "a and b", "a, b and c".
fn join(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Site patterns, shortened when there are many.
fn sites(hosts: &[String]) -> String {
    const MAX: usize = 8;
    if hosts.len() <= MAX {
        hosts.join(", ")
    } else {
        format!("{} and {} more", hosts[..MAX].join(", "), hosts.len() - MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{Subject, family, is_trusted, subject_for};
    use vogter_model::TrustRule;

    fn ext(source: ExtensionSource, perms: &[&str], hosts: &[&str]) -> BrowserExtension {
        BrowserExtension {
            browser: "Brave".into(),
            profile: "Default".into(),
            profile_path: "/Users/me/Library/Application Support/BraveSoftware/Brave-Browser/Default"
                .into(),
            id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            name: "Thing".into(),
            version: "1.0".into(),
            enabled: true,
            source,
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            host_permissions: hosts.iter().map(|s| s.to_string()).collect(),
            path: Some(
                "/Users/me/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
            ),
            install_time: None,
            signing: None,
        }
    }

    #[test]
    fn all_sites_patterns() {
        for p in [
            "<all_urls>",
            "*://*/*",
            "https://*/*",
            "http://*/",
            "*://*/foo*",
        ] {
            assert!(is_all_sites(p), "{p}");
        }
        for p in [
            "https://*.google.com/*",
            "file:///*",
            "*://example.com/*",
            "tabs",
        ] {
            assert!(!is_all_sites(p), "{p}");
        }
    }

    #[test]
    fn store_with_narrow_permissions_is_info() {
        let f = extension(&ext(
            ExtensionSource::Store,
            &["storage", "alarms"],
            &["https://*.example.com/*"],
        ));
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.check, "browser.extension.installed");
        assert_eq!(f.category, Category::Browser);
        assert_eq!(
            f.source.as_deref(),
            Some(ext(ExtensionSource::Store, &[], &[]).profile_path.as_str())
        );
    }

    #[test]
    fn all_sites_with_cookies_is_medium() {
        let f = extension(&ext(
            ExtensionSource::Store,
            &["cookies", "storage"],
            &["<all_urls>"],
        ));
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.check, "browser.extension.all_sites");
        assert!(f.title.contains("all your data on all websites"));
        assert!(f.detail.contains("login cookies"));
        assert!(f.detail.contains("Password managers"));
        assert!(f.detail.contains("brave://extensions"));
        // All sites alone (a plain content script) stays an inventory line.
        let plain = extension(&ext(ExtensionSource::Store, &["storage"], &["*://*/*"]));
        assert_eq!(plain.severity, Severity::Info);
        assert!(plain.detail.contains("every website"));
    }

    #[test]
    fn unpacked_developer_extension_is_high() {
        let f = extension(&ext(ExtensionSource::Developer, &[], &[]));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.check, "browser.extension.developer");
        let s = extension(&ext(
            ExtensionSource::Sideloaded,
            &["cookies"],
            &["<all_urls>"],
        ));
        assert_eq!(s.severity, Severity::High);
        assert_eq!(s.check, "browser.extension.sideloaded");
        assert!(s.detail.contains("every website"));
    }

    #[test]
    fn policy_is_medium_and_mentions_employer() {
        let f = extension(&ext(ExtensionSource::Policy, &[], &[]));
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.check, "browser.extension.policy");
        assert!(f.detail.contains("employer"));
    }

    #[test]
    fn disabled_is_at_most_info() {
        let mut e = ext(ExtensionSource::Sideloaded, &["cookies"], &["<all_urls>"]);
        e.enabled = false;
        let f = extension(&e);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains("turned off"));
    }

    #[test]
    fn native_messaging_is_mentioned() {
        let f = extension(&ext(
            ExtensionSource::Store,
            &["nativeMessaging"],
            &["<all_urls>"],
        ));
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.detail.contains("program on your Mac"));
    }

    #[test]
    fn safari_all_sites_stays_info() {
        let mut e = ext(ExtensionSource::Store, &["cookies"], &["<all_urls>"]);
        e.browser = "Safari".into();
        let f = extension(&e);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.detail.contains("per site"));
    }

    #[test]
    fn trusting_an_extension_silences_it() {
        // The extension folder is a directory, which has no content hash.
        let dir = std::env::temp_dir().display().to_string();
        let mut e = ext(ExtensionSource::Store, &["cookies"], &["<all_urls>"]);
        e.path = Some(dir);
        let f = extension(&e);
        let dir_hash = |_: &str| None;
        let (subject, _) = subject_for(&Subject::from(&f), &dir_hash);
        assert!(matches!(subject, vogter_model::TrustSubject::Exact { .. }));
        let rule = TrustRule {
            id: 1,
            check: family(&f.check),
            subject,
            label: String::new(),
            created_at: 0,
        };
        assert!(is_trusted(
            &Subject::from(&f),
            std::slice::from_ref(&rule),
            &dir_hash
        ));
        // A different extension isn't covered.
        let mut other = ext(ExtensionSource::Store, &["cookies"], &["<all_urls>"]);
        other.name = "Other".into();
        other.path = Some("/elsewhere".into());
        assert!(!is_trusted(
            &Subject::from(&extension(&other)),
            &[rule],
            &dir_hash
        ));
        assert_eq!(family("browser.extension.all_sites"), "browser");
    }
}
