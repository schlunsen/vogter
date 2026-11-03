//! Places where secrets live, and who may read them.

use vogter_model::{Activity, ActivityKind, ExecInfo, Severity};

#[derive(Debug, Clone)]
pub struct SensitiveArea {
    /// Absolute path prefix (directories end with '/').
    pub prefix: String,
    pub label: &'static str,
    /// Developer Team IDs allowed to read it besides Apple's own programs.
    pub owners: &'static [&'static str],
    pub severity: Severity,
}

const GOOGLE: &str = "EQHXZ8M8AV";
const BRAVE: &str = "KL8N8XSYF4";
const MICROSOFT: &str = "UBF8T346G9";
const MOZILLA: &str = "43AQ936H96";

/// Secret stores under one user's home directory.
pub fn sensitive_areas(home: &str) -> Vec<SensitiveArea> {
    let h = home.trim_end_matches('/');
    let area = |rel: &str, label, owners, severity| SensitiveArea {
        prefix: format!("{h}/{rel}"),
        label,
        owners,
        severity,
    };
    vec![
        area("Library/Keychains/", "your Keychain", &[], Severity::High),
        area("Library/Cookies/", "Safari cookies", &[], Severity::High),
        area(
            "Library/Application Support/Google/Chrome/",
            "Chrome cookies and saved passwords",
            &[GOOGLE],
            Severity::High,
        ),
        area(
            "Library/Application Support/BraveSoftware/",
            "Brave cookies and saved passwords",
            &[BRAVE],
            Severity::High,
        ),
        area(
            "Library/Application Support/Microsoft Edge/",
            "Edge cookies and saved passwords",
            &[MICROSOFT],
            Severity::High,
        ),
        area(
            "Library/Application Support/Firefox/Profiles/",
            "Firefox cookies and saved passwords",
            &[MOZILLA],
            Severity::High,
        ),
        area(
            "Library/Messages/",
            "your Messages history",
            &[],
            Severity::Medium,
        ),
        area(".ssh/", "your SSH keys", &[], Severity::Medium),
        area(".aws/", "your AWS credentials", &[], Severity::Medium),
        area(".gnupg/", "your GPG keys", &[], Severity::Medium),
    ]
}

/// A process opened `path`. Is that a process that has no business there?
pub fn assess_file_read(
    reader: &ExecInfo,
    path: &str,
    areas: &[SensitiveArea],
) -> Option<Activity> {
    let area = areas.iter().find(|a| path.starts_with(&a.prefix))?;
    if reader.signing.is_apple() {
        return None;
    }
    if let Some(team) = &reader.signing.team_id
        && area.owners.contains(&team.as_str())
    {
        return None;
    }
    let severity = if reader.signing.is_weak() {
        Severity::Critical
    } else {
        area.severity
    };
    Some(
        Activity::new(
            ActivityKind::SensitiveFileRead,
            severity,
            format!("{} read {}", reader.name(), area.label),
        )
        .detail(format!("{path} — reader is {}", reader.signing.describe()))
        .from_exec(reader),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::{SignatureKind, Signing};

    fn reader(kind: SignatureKind, team: Option<&str>) -> ExecInfo {
        ExecInfo {
            pid: 1,
            ppid: 1,
            uid: 501,
            path: "/x/stealer".into(),
            args: vec![],
            signing: Signing {
                kind,
                identifier: None,
                team_id: team.map(str::to_string),
                notarized: true,
            },
            parent_path: None,
        }
    }

    #[test]
    fn browser_reading_its_own_profile_is_fine() {
        let areas = sensitive_areas("/Users/me");
        let p = "/Users/me/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies";
        assert!(
            assess_file_read(&reader(SignatureKind::ThirdParty, Some(BRAVE)), p, &areas).is_none()
        );
        let other = assess_file_read(
            &reader(SignatureKind::ThirdParty, Some("OTHERTEAM1")),
            p,
            &areas,
        )
        .unwrap();
        assert_eq!(other.severity, Severity::High);
        let adhoc = assess_file_read(&reader(SignatureKind::AdHoc, None), p, &areas).unwrap();
        assert_eq!(adhoc.severity, Severity::Critical);
    }

    #[test]
    fn apple_and_unrelated_paths_are_quiet() {
        let areas = sensitive_areas("/Users/me/");
        assert!(
            assess_file_read(
                &reader(SignatureKind::Apple, None),
                "/Users/me/Library/Keychains/login.keychain-db",
                &areas
            )
            .is_none()
        );
        assert!(
            assess_file_read(
                &reader(SignatureKind::AdHoc, None),
                "/Users/me/Documents/a.txt",
                &areas
            )
            .is_none()
        );
    }
}
