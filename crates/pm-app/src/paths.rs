//! File locations and command-line arguments.

use std::path::PathBuf;

pub const APP_DIR: &str = "ProxyManager";

/// Directory for the config and logs:
/// `%APPDATA%\ProxyManager` on Windows, `$XDG_CONFIG_HOME/ProxyManager` or
/// `~/.config/ProxyManager` elsewhere, the current directory as a last resort.
pub fn config_dir_with(env: impl Fn(&str) -> Option<String>, windows: bool) -> PathBuf {
    let non_empty = |key: &str| env(key).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if windows {
        non_empty("APPDATA")
    } else {
        non_empty("XDG_CONFIG_HOME").or_else(|| non_empty("HOME").map(|h| h.join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join(APP_DIR)
}

pub fn config_dir() -> PathBuf {
    config_dir_with(|k| std::env::var(k).ok(), cfg!(windows))
}

pub fn default_config_file() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn log_dir() -> PathBuf {
    config_dir().join("logs")
}

/// Where `WinDivert.dll` and `WinDivert64.sys` live: `PM_WINDIVERT_DIR` or the executable's directory.
pub fn windivert_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PM_WINDIVERT_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Parsed command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    /// `--config <file>`: alternative config file.
    pub config: Option<PathBuf>,
    /// `--start`: start proxying immediately.
    pub start: bool,
    /// `--minimized`: start hidden in the tray.
    pub minimized: bool,
    /// `--no-elevate`: do not ask for administrator rights.
    pub no_elevate: bool,
}

pub const USAGE: &str = "proxy-manager [--config <файл>] [--start] [--minimized] [--no-elevate]";

impl Args {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut parsed = Args::default();
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--config" | "-c" => {
                    let path = it
                        .next()
                        .ok_or_else(|| format!("после {arg} нужен путь к файлу"))?;
                    parsed.config = Some(PathBuf::from(path));
                }
                "--start" => parsed.start = true,
                "--minimized" => parsed.minimized = true,
                "--no-elevate" => parsed.no_elevate = true,
                other => {
                    return Err(format!(
                        "неизвестный аргумент «{other}». Использование: {USAGE}"
                    ));
                }
            }
        }
        Ok(parsed)
    }

    /// Arguments to pass when re-launching elevated.
    pub fn to_command_line(&self) -> String {
        let mut parts = Vec::new();
        if let Some(cfg) = &self.config {
            parts.push(format!("--config \"{}\"", cfg.display()));
        }
        if self.start {
            parts.push("--start".to_string());
        }
        if self.minimized {
            parts.push("--minimized".to_string());
        }
        if self.no_elevate {
            parts.push("--no-elevate".to_string());
        }
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn config_dir_resolution() {
        assert_eq!(
            config_dir_with(env(&[("APPDATA", "C:\\Users\\me\\AppData\\Roaming")]), true),
            PathBuf::from("C:\\Users\\me\\AppData\\Roaming").join(APP_DIR)
        );
        assert_eq!(
            config_dir_with(env(&[("XDG_CONFIG_HOME", "/x")]), false),
            PathBuf::from("/x/ProxyManager")
        );
        assert_eq!(
            config_dir_with(env(&[("HOME", "/home/u")]), false),
            PathBuf::from("/home/u/.config/ProxyManager")
        );
        assert_eq!(
            config_dir_with(env(&[("XDG_CONFIG_HOME", ""), ("HOME", "/h")]), false),
            PathBuf::from("/h/.config/ProxyManager")
        );
        assert_eq!(
            config_dir_with(env(&[]), true),
            PathBuf::from("./ProxyManager")
        );
        assert!(config_dir().ends_with(APP_DIR));
        assert!(default_config_file().ends_with("config.toml"));
        assert!(log_dir().ends_with("logs"));
        assert!(windivert_dir().is_absolute() || std::env::var_os("PM_WINDIVERT_DIR").is_some());
    }

    #[test]
    fn parse_args() {
        let a = |v: &[&str]| Args::parse(v.iter().map(|s| s.to_string()));
        assert_eq!(a(&[]).unwrap(), Args::default());
        let parsed = a(&[
            "--config",
            "C:\\my cfg.toml",
            "--start",
            "--minimized",
            "--no-elevate",
        ])
        .unwrap();
        assert_eq!(parsed.config, Some(PathBuf::from("C:\\my cfg.toml")));
        assert!(parsed.start && parsed.minimized && parsed.no_elevate);
        assert_eq!(
            parsed.to_command_line(),
            "--config \"C:\\my cfg.toml\" --start --minimized --no-elevate"
        );
        assert_eq!(a(&["-c", "x"]).unwrap().config, Some(PathBuf::from("x")));
        assert!(a(&["--config"]).unwrap_err().contains("путь"));
        assert!(a(&["--bogus"]).unwrap_err().contains("--bogus"));
        assert_eq!(Args::default().to_command_line(), "");
    }
}
