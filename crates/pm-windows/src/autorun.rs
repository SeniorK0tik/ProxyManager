//! "Launch at login" via Task Scheduler.
//!
//! A scheduled task with the highest run level starts the manager elevated
//! without a UAC prompt, which a `Run` registry key cannot do.

use std::path::Path;

pub const TASK_NAME: &str = "Proxy Manager";

/// Arguments for `schtasks` creating the logon task.
pub fn create_task_args(exe: &Path) -> String {
    format!(
        "/Create /F /TN \"{TASK_NAME}\" /SC ONLOGON /RL HIGHEST /TR \"\\\"{}\\\" --start --minimized\"",
        exe.display()
    )
}

pub fn delete_task_args() -> String {
    format!("/Delete /F /TN \"{TASK_NAME}\"")
}

pub fn query_task_args() -> String {
    format!("/Query /TN \"{TASK_NAME}\"")
}

#[cfg(windows)]
mod os {
    use super::*;
    use std::io;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Output, Stdio};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn schtasks(args: &str) -> io::Result<Output> {
        Command::new("schtasks")
            .raw_arg(args)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
    }

    fn check(out: Output) -> io::Result<()> {
        if out.status.success() {
            Ok(())
        } else {
            let msg = String::from_utf8_lossy(&out.stderr);
            Err(io::Error::other(format!("schtasks: {}", msg.trim())))
        }
    }

    pub fn is_enabled() -> bool {
        schtasks(&query_task_args()).is_ok_and(|o| o.status.success())
    }

    pub fn set_enabled(exe: &Path, enabled: bool) -> io::Result<()> {
        if enabled {
            check(schtasks(&create_task_args(exe))?)
        } else {
            check(schtasks(&delete_task_args())?)
        }
    }
}

#[cfg(windows)]
pub use os::{is_enabled, set_enabled};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        let args = create_task_args(Path::new("C:\\Apps\\Proxy Manager\\proxy-manager.exe"));
        assert_eq!(
            args,
            "/Create /F /TN \"Proxy Manager\" /SC ONLOGON /RL HIGHEST /TR \"\\\"C:\\Apps\\Proxy Manager\\proxy-manager.exe\\\" --start --minimized\""
        );
        assert_eq!(delete_task_args(), "/Delete /F /TN \"Proxy Manager\"");
        assert_eq!(query_task_args(), "/Query /TN \"Proxy Manager\"");
    }
}
