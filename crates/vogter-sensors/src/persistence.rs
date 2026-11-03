//! Things configured to start automatically: launchd jobs and cron.

use std::path::{Path, PathBuf};
use std::process::Command;

use plist::Value;
use vogter_model::{CronEntry, LaunchItem, LaunchKind};

use crate::codesign;

pub fn launch_items(errors: &mut Vec<String>) -> Vec<LaunchItem> {
    let mut dirs = vec![
        (
            LaunchKind::SystemDaemon,
            PathBuf::from("/Library/LaunchDaemons"),
        ),
        (
            LaunchKind::SystemAgent,
            PathBuf::from("/Library/LaunchAgents"),
        ),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push((
            LaunchKind::UserAgent,
            Path::new(&home).join("Library/LaunchAgents"),
        ));
    }

    let mut items = Vec::new();
    for (kind, dir) in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "plist") {
                match parse(kind, &path) {
                    Ok(item) => items.push(item),
                    Err(e) => errors.push(format!("{}: {e}", path.display())),
                }
            }
        }
    }
    items.sort_by(|a, b| a.plist_path.cmp(&b.plist_path));
    items
}

fn parse(kind: LaunchKind, path: &Path) -> Result<LaunchItem, String> {
    let value = Value::from_file(path).map_err(|e| e.to_string())?;
    let dict = value.as_dictionary().ok_or("not a dictionary")?;
    let string = |k: &str| dict.get(k).and_then(Value::as_string).map(str::to_string);
    let flag = |k: &str| match dict.get(k) {
        Some(Value::Boolean(b)) => *b,
        Some(Value::Dictionary(_)) => true, // KeepAlive conditions
        _ => false,
    };
    let arguments: Vec<String> = dict
        .get("ProgramArguments")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_string)
                .map(str::to_string)
                .collect()
        })
        .map(vogter_model::redact::redact_args)
        .unwrap_or_default();
    let program = string("Program").or_else(|| arguments.first().cloned());
    let program_exists = program.as_deref().is_some_and(|p| Path::new(p).exists());
    let signing = program
        .as_deref()
        .filter(|_| program_exists)
        .map(codesign::for_path);

    Ok(LaunchItem {
        kind,
        plist_path: path.display().to_string(),
        label: string("Label"),
        program,
        arguments,
        run_at_load: flag("RunAtLoad"),
        keep_alive: flag("KeepAlive"),
        disabled: flag("Disabled"),
        program_exists,
        signing,
    })
}

/// The watched user's crontab (as root, also root's own).
pub fn cron() -> Vec<CronEntry> {
    let mut users: Vec<String> = crate::user::target().map(|u| u.name).into_iter().collect();
    if crate::user::is_root() {
        users.push("root".into());
    }
    users.dedup();
    users.into_iter().flat_map(crontab).collect()
}

fn crontab(user: String) -> Vec<CronEntry> {
    let mut cmd = Command::new("/usr/bin/crontab");
    if crate::user::is_root() {
        cmd.args(["-u", &user]);
    }
    cmd.arg("-l");
    let Ok(out) = cmd.output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| CronEntry {
            user: user.clone(),
            line: line.to_string(),
        })
        .collect()
}
