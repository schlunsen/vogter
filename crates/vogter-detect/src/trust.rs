//! Does a trust rule cover a finding or activity?

use vogter_model::{Activity, Finding, SignatureKind, Signing, TrustRule, TrustSubject};

/// What is being judged, reduced to what trust rules can match on.
pub struct Subject<'a> {
    pub check: String,
    pub key: String,
    pub path: Option<&'a str>,
    pub signing: Option<&'a Signing>,
}

impl<'a> From<&'a Finding> for Subject<'a> {
    fn from(f: &'a Finding) -> Self {
        Subject {
            check: f.check.clone(),
            key: f.key(),
            path: f.path.as_deref(),
            signing: f.signing.as_ref(),
        }
    }
}

impl<'a> From<&'a Activity> for Subject<'a> {
    fn from(a: &'a Activity) -> Self {
        Subject {
            check: a.check(),
            key: a.key(),
            path: a.path.as_deref(),
            signing: a.signing.as_ref(),
        }
    }
}

/// Trust covers a family of related checks, so trusting a program from its
/// launch alert also covers the matching scan finding (and vice versa).
pub fn family(check: &str) -> String {
    let group = |prefix: &str| check.starts_with(prefix);
    let f = if check == "activity.process_started" || group("process.") {
        "process"
    } else if check == "activity.persistence_changed" || group("persistence.") {
        "persistence"
    } else if check == "activity.permission_changed" || group("tcc.") {
        "permissions"
    } else if group("keylogger.") {
        "keylogger"
    } else if group("network.") {
        "network"
    } else {
        check
    };
    f.to_string()
}

/// `hash` returns a file's SHA-256 (hex), or None if it can't be read.
pub fn is_trusted(
    s: &Subject<'_>,
    rules: &[TrustRule],
    hash: &dyn Fn(&str) -> Option<String>,
) -> bool {
    rules.iter().any(|r| matches(r, s, hash))
}

fn matches(rule: &TrustRule, s: &Subject<'_>, hash: &dyn Fn(&str) -> Option<String>) -> bool {
    match &rule.subject {
        TrustSubject::Exact { key } => *key == s.key,
        _ if rule.check != "*" && rule.check != family(&s.check) => false,
        TrustSubject::Developer {
            team_id,
            identifier,
        } => s.signing.is_some_and(|sig| {
            sig.kind == SignatureKind::ThirdParty
                && sig.team_id.as_ref() == Some(team_id)
                && identifier
                    .as_ref()
                    .is_none_or(|id| sig.identifier.as_ref() == Some(id))
        }),
        TrustSubject::File { path, sha256 } => {
            s.path == Some(path.as_str())
                && match sha256 {
                    Some(want) => hash(path).as_ref() == Some(want),
                    None => !std::path::Path::new(path).exists(),
                }
        }
    }
}

/// The most specific safe subject for trusting this thing.
///
/// Apple-signed programs are shared by everything (`/bin/bash` runs every
/// script), so trusting one would hide far too much: those get an exact rule.
pub fn subject_for(
    s: &Subject<'_>,
    hash: &dyn Fn(&str) -> Option<String>,
) -> (TrustSubject, String) {
    let name = s
        .path
        .map(|p| p.rsplit('/').next().unwrap_or(p).to_string());
    match (s.signing, s.path) {
        (Some(sig), _) if sig.kind == SignatureKind::ThirdParty && sig.team_id.is_some() => {
            let team = sig.team_id.clone().unwrap();
            let label = format!(
                "{} (developer {team})",
                name.as_deref().or(sig.identifier.as_deref()).unwrap_or("?")
            );
            (
                TrustSubject::Developer {
                    team_id: team,
                    identifier: sig.identifier.clone(),
                },
                label,
            )
        }
        (sig, Some(path)) if !sig.is_some_and(|s| s.is_apple()) => {
            let sha256 = hash(path);
            let label = match &sha256 {
                Some(h) => format!("{path} (contents {})", &h[..12]),
                None => format!("{path} (missing file)"),
            };
            (
                TrustSubject::File {
                    path: path.to_string(),
                    sha256,
                },
                label,
            )
        }
        _ => (
            TrustSubject::Exact { key: s.key.clone() },
            s.key.split('|').nth(1).unwrap_or(&s.key).to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::{Category, Severity};

    fn finding(check: &str, path: &str, signing: Signing) -> Finding {
        Finding {
            severity: Severity::Medium,
            category: Category::Keylogger,
            check: check.into(),
            title: "t".into(),
            detail: "d".into(),
            pid: None,
            path: Some(path.into()),
            signing: Some(signing),
        }
    }

    fn sig(kind: SignatureKind, team: Option<&str>, id: Option<&str>) -> Signing {
        Signing {
            kind,
            identifier: id.map(str::to_string),
            team_id: team.map(str::to_string),
            notarized: true,
        }
    }

    fn rule(check: &str, subject: TrustSubject) -> TrustRule {
        TrustRule {
            id: 1,
            check: check.into(),
            subject,
            label: String::new(),
            created_at: 0,
        }
    }

    fn no_hash(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn developer_rule_needs_valid_signature_and_matching_check() {
        let raycast = finding(
            "keylogger.event_tap",
            "/Applications/Raycast.app/x",
            sig(SignatureKind::ThirdParty, Some("TEAM"), Some("com.raycast")),
        );
        let (subject, _) = subject_for(&Subject::from(&raycast), &no_hash);
        let r = rule(&family("keylogger.event_tap"), subject);
        assert!(is_trusted(
            &Subject::from(&raycast),
            std::slice::from_ref(&r),
            &no_hash
        ));

        // Same team id claimed by an ad-hoc binary: not trusted.
        let fake = finding(
            "keylogger.event_tap",
            "/tmp/x",
            sig(SignatureKind::AdHoc, Some("TEAM"), Some("com.raycast")),
        );
        assert!(!is_trusted(
            &Subject::from(&fake),
            std::slice::from_ref(&r),
            &no_hash
        ));

        // Other check: not covered unless the rule is "*".
        let other = finding(
            "tcc.screencapture",
            "/Applications/Raycast.app/x",
            raycast.signing.clone().unwrap(),
        );
        assert!(!is_trusted(
            &Subject::from(&other),
            std::slice::from_ref(&r),
            &no_hash
        ));
        let all = TrustRule {
            check: "*".into(),
            ..r
        };
        assert!(is_trusted(&Subject::from(&other), &[all], &no_hash));
    }

    #[test]
    fn file_rule_breaks_when_contents_change() {
        let f = finding(
            "process.weak_signature",
            "/usr/local/bin/tool",
            sig(SignatureKind::AdHoc, None, None),
        );
        let hash_v1 = |_: &str| Some("aaaa1111bbbb2222".to_string());
        let (subject, label) = subject_for(&Subject::from(&f), &hash_v1);
        assert!(label.contains("aaaa1111bbbb"));
        let r = rule(&family("process.weak_signature"), subject);
        assert!(is_trusted(
            &Subject::from(&f),
            std::slice::from_ref(&r),
            &hash_v1
        ));
        let hash_v2 = |_: &str| Some("cccc".to_string());
        assert!(!is_trusted(&Subject::from(&f), &[r], &hash_v2));
    }

    #[test]
    fn families_join_scan_and_live_checks() {
        assert_eq!(
            family("activity.process_started"),
            family("process.suspicious_location")
        );
        assert_eq!(
            family("activity.persistence_changed"),
            family("persistence.launch_item")
        );
        assert_ne!(
            family("keylogger.event_tap"),
            family("process.weak_signature")
        );
        assert_eq!(family("activity.sudo"), "activity.sudo");
    }

    #[test]
    fn apple_programs_get_exact_rules() {
        let f = finding(
            "persistence.script",
            "/bin/bash",
            sig(SignatureKind::Apple, None, None),
        );
        let (subject, _) = subject_for(&Subject::from(&f), &no_hash);
        assert!(matches!(subject, TrustSubject::Exact { .. }));
        let r = rule("persistence.script", subject);
        let other = Finding {
            title: "another script".into(),
            ..f.clone()
        };
        assert!(is_trusted(
            &Subject::from(&f),
            std::slice::from_ref(&r),
            &no_hash
        ));
        assert!(!is_trusted(&Subject::from(&other), &[r], &no_hash));
    }
}
