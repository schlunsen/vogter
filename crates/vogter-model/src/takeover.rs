//! Facts about other ways to keep a foothold on a Mac or take it over, beyond
//! launchd and cron: shell startup files, SSH keys, `/etc/hosts`, sudoers,
//! configuration profiles, login hooks, system/kernel extensions and
//! Background Task Management items.

use serde::{Deserialize, Serialize};

use crate::Signing;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Takeover {
    #[serde(default)]
    pub shell_files: Vec<ShellFile>,
    #[serde(default)]
    pub ssh_keys: Vec<SshKey>,
    #[serde(default)]
    pub hosts: Vec<HostsEntry>,
    #[serde(default)]
    pub sudoers: Vec<SudoersLine>,
    #[serde(default)]
    pub profiles: Vec<ConfigProfile>,
    #[serde(default)]
    pub login_hooks: Vec<LoginHook>,
    #[serde(default)]
    pub system_extensions: Vec<SystemExtension>,
    #[serde(default)]
    pub kernel_extensions: Vec<KernelExtension>,
    #[serde(default)]
    pub background_items: Vec<BackgroundItem>,
}

/// A shell startup file (`~/.zshrc`, `/etc/profile`, ...) that exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellFile {
    pub path: String,
    /// `/etc/...`: read by every user's shells.
    pub system: bool,
    /// Commands only (comments and blank lines dropped, continuations joined),
    /// with secrets redacted.
    pub lines: Vec<NumberedLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberedLine {
    /// 1-based line number in the file.
    pub line: usize,
    pub text: String,
}

/// A key in an `authorized_keys` file: whoever holds the private half can log in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub user: String,
    pub file: String,
    pub line: usize,
    /// `ssh-ed25519`, `ssh-rsa`, ...
    pub key_type: String,
    /// `SHA256:…` as `ssh-keygen -l` prints it; `None` if the key data is malformed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Options before the key (`command="…"`, `from="…"`), redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostsEntry {
    pub file: String,
    pub line: usize,
    pub address: String,
    pub names: Vec<String>,
}

/// One rule or setting in a sudoers file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SudoersLine {
    pub file: String,
    pub line: usize,
    pub text: String,
}

/// An installed configuration profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigProfile {
    /// `computer` or the user name it is installed for.
    pub scope: String,
    pub identifier: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub payload_types: Vec<String>,
    /// The profile can't be removed by the user.
    pub removal_disallowed: bool,
}

/// `LoginHook` / `LogoutHook` in a loginwindow preferences file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginHook {
    /// `LoginHook` or `LogoutHook`.
    pub kind: String,
    pub plist: String,
    pub command: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
}

/// A system extension (network filter, Endpoint Security, driver...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemExtension {
    /// e.g. `com.apple.system_extension.network_extension`.
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    pub bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub name: String,
    /// e.g. `activated enabled`.
    pub state: String,
    pub enabled: bool,
    pub active: bool,
}

/// A loaded kernel extension that isn't Apple's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelExtension {
    pub bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A login or background item known to Background Task Management (`sfltool dumpbtm`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackgroundItem {
    pub uid: Option<i64>,
    pub name: String,
    /// e.g. `app`, `login item`, `agent`, `daemon`, `legacy agent`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
}
