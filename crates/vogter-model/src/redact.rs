//! Strip secrets from command lines before they are stored or shown.
//!
//! Programs often receive credentials as arguments (`curl -H "Authorization: Bearer …"`,
//! `--password=…`, `https://user:pass@host`). Vogter records command lines, so it must
//! never keep those.

const MASK: &str = "[redacted]";

/// Argument/flag names whose value is a secret.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "api_key",
    "access-key",
    "access_key",
    "private-key",
    "auth",
];

/// Token prefixes used by common services.
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "sk-",
    "sk_live_",
    "sk_test_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "apikey-",
    "glpat-",
    "npm_",
];

fn secretish(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|w| n.contains(w))
}

/// Redact a whole argv. Also handles `--password VALUE` (secret in the next argument).
pub fn redact_args(args: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut hide_next = false;
    for a in args {
        if hide_next {
            out.push(MASK.to_string());
            hide_next = false;
            continue;
        }
        // `--token VALUE` / `-password VALUE` (but not `--password=` handled below).
        if a.starts_with('-') && !a.contains('=') && secretish(a.trim_start_matches('-')) {
            hide_next = true;
            out.push(a);
            continue;
        }
        out.push(redact(&a));
    }
    out
}

/// Redact secrets inside one string.
pub fn redact(s: &str) -> String {
    // Header-like `Name: value` where the name is secret-ish (Authorization, X-Api-Key, Cookie...).
    if let Some((name, _)) = s.split_once(':')
        && !name.contains(' ')
        && !name.contains('/')
        && (secretish(name) || name.eq_ignore_ascii_case("cookie"))
    {
        return format!("{name}: {MASK}");
    }
    // `--flag=value` / `KEY=value` with a secret-ish name.
    if let Some((name, _)) = s.split_once('=')
        && !name.contains(' ')
        && secretish(name)
    {
        return format!("{name}={MASK}");
    }
    let mut out = s.to_string();
    // Bearer/Basic tokens anywhere in the string.
    for scheme in ["Bearer ", "bearer ", "Basic ", "basic "] {
        out = mask_after(&out, scheme);
    }
    // Credentials in URLs: scheme://user:pass@host
    out = mask_url_passwords(&out);
    // Known token formats.
    out = out
        .split(' ')
        .map(|w| {
            let bare = w.trim_matches(|c: char| c == '"' || c == '\'');
            if TOKEN_PREFIXES
                .iter()
                .any(|p| bare.starts_with(p) && bare.len() >= p.len() + 8)
            {
                MASK.to_string()
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    out
}

fn mask_after(s: &str, marker: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(marker) {
        out.push_str(&rest[..i + marker.len()]);
        rest = &rest[i + marker.len()..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(rest.len());
        if end > 0 {
            out.push_str(MASK);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn mask_url_passwords(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        out.push_str(&rest[..i + 3]);
        rest = &rest[i + 3..];
        let auth_end = rest
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(rest.len());
        if let Some(at) = rest[..auth_end].rfind('@')
            && let Some(colon) = rest[..at].find(':')
        {
            out.push_str(&rest[..colon + 1]);
            out.push_str(MASK);
            rest = &rest[at..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn curl_headers_and_bearer() {
        let r = redact_args(v(&[
            "curl",
            "-H",
            "Authorization: Bearer apikey-0123456789abcdef",
            "https://api.example.com",
        ]));
        assert_eq!(
            r,
            v(&[
                "curl",
                "-H",
                "Authorization: [redacted]",
                "https://api.example.com"
            ])
        );
        assert_eq!(redact("x Bearer abc.def y"), "x Bearer [redacted] y");
        assert_eq!(redact("X-Api-Key: 123"), "X-Api-Key: [redacted]");
    }

    #[test]
    fn flags_env_and_urls() {
        assert_eq!(
            redact_args(v(&["tool", "--password", "hunter2", "-v"])),
            v(&["tool", "--password", "[redacted]", "-v"])
        );
        assert_eq!(redact("--api-key=abc"), "--api-key=[redacted]");
        assert_eq!(redact("GITHUB_TOKEN=ghp_x"), "GITHUB_TOKEN=[redacted]");
        assert_eq!(
            redact("git clone https://me:s3cret@github.com/a/b"),
            "git clone https://me:[redacted]@github.com/a/b"
        );
        assert_eq!(
            redact("echo ghp_abcdefghijklmnop done"),
            "echo [redacted] done"
        );
    }

    #[test]
    fn leaves_ordinary_commands_alone() {
        let cmd = v(&["security", "find-generic-password", "-w", "-s", "svc"]);
        assert_eq!(redact_args(cmd.clone()), cmd);
        assert_eq!(
            redact("https://example.com/path?a=b"),
            "https://example.com/path?a=b"
        );
        assert_eq!(
            redact(r#"display dialog "Enter your password" with hidden answer"#),
            r#"display dialog "Enter your password" with hidden answer"#
        );
        assert_eq!(redact("/usr/bin/git"), "/usr/bin/git");
    }
}
