//! Windows Firewall rule for the relay.
//!
//! Redirected connections reach the relay as *inbound* connections from the remote
//! server's address, so the firewall must allow inbound TCP to our executable.

use std::path::Path;

pub const RULE_NAME: &str = "Proxy Manager relay";

/// Arguments for `netsh` deleting the rule (all copies, if any).
pub fn delete_rule_args() -> String {
    format!("advfirewall firewall delete rule name=\"{RULE_NAME}\"")
}

/// Arguments for `netsh` adding the rule for `exe`.
pub fn add_rule_args(exe: &Path) -> String {
    format!(
        "advfirewall firewall add rule name=\"{RULE_NAME}\" dir=in action=allow protocol=TCP profile=any enable=yes program=\"{}\"",
        exe.display()
    )
}

#[cfg(windows)]
mod os {
    use super::*;
    use std::io;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn netsh(args: &str) -> io::Result<std::process::Output> {
        Command::new("netsh")
            .raw_arg(args)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
    }

    /// Re-creates the inbound allow rule for `exe`. Requires administrator rights.
    pub fn ensure_rule(exe: &Path) -> io::Result<()> {
        let _ = netsh(&delete_rule_args());
        let out = netsh(&add_rule_args(exe))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "netsh завершился с ошибкой: {}",
                String::from_utf8_lossy(&out.stdout).trim()
            )))
        }
    }
}

#[cfg(windows)]
pub use os::ensure_rule;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        assert_eq!(
            delete_rule_args(),
            "advfirewall firewall delete rule name=\"Proxy Manager relay\""
        );
        let args = add_rule_args(Path::new(
            "C:\\Program Files\\Proxy Manager\\proxy-manager.exe",
        ));
        assert!(args.starts_with(
            "advfirewall firewall add rule name=\"Proxy Manager relay\" dir=in action=allow"
        ));
        assert!(args.ends_with("program=\"C:\\Program Files\\Proxy Manager\\proxy-manager.exe\""));
    }
}
