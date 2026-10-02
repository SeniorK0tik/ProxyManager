//! Running processes, grouped by executable, for the "add from running" list.

use std::collections::BTreeMap;

/// One executable with all its running instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub name: String,
    pub path: Option<String>,
    pub pids: Vec<u32>,
}

impl ProcessEntry {
    /// The pattern to add to a rule: the full path when known, the file name otherwise.
    pub fn pattern(&self) -> &str {
        self.path.as_deref().unwrap_or(&self.name)
    }
}

/// Groups `(pid, name, path)` triples by executable, sorted by name.
pub fn group(raw: impl IntoIterator<Item = (u32, String, Option<String>)>) -> Vec<ProcessEntry> {
    let mut map: BTreeMap<(String, String), ProcessEntry> = BTreeMap::new();
    for (pid, name, path) in raw {
        if name.is_empty() {
            continue;
        }
        let key = (
            name.to_lowercase(),
            path.as_deref().unwrap_or_default().to_lowercase(),
        );
        map.entry(key)
            .or_insert_with(|| ProcessEntry {
                name: name.clone(),
                path: path.clone(),
                pids: Vec::new(),
            })
            .pids
            .push(pid);
    }
    map.into_values()
        .map(|mut e| {
            e.pids.sort_unstable();
            e
        })
        .collect()
}

/// Case-insensitive substring search over name and path.
pub fn filter<'a>(entries: &'a [ProcessEntry], query: &str) -> Vec<&'a ProcessEntry> {
    let q = query.trim().to_lowercase();
    entries
        .iter()
        .filter(|e| {
            q.is_empty()
                || e.name.to_lowercase().contains(&q)
                || e.path
                    .as_deref()
                    .is_some_and(|p| p.to_lowercase().contains(&q))
        })
        .collect()
}

/// Lists running processes.
pub fn snapshot() -> Vec<ProcessEntry> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    // On Linux threads are reported as tasks; only real processes are interesting.
    group(
        sys.processes()
            .values()
            .filter(|p| p.thread_kind().is_none())
            .map(|p| {
                (
                    p.pid().as_u32(),
                    p.name().to_string_lossy().into_owned(),
                    p.exe()
                        .map(|e| e.to_string_lossy().into_owned())
                        .filter(|e| !e.is_empty()),
                )
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> Vec<(u32, String, Option<String>)> {
        vec![
            (
                30,
                "chrome.exe".into(),
                Some("C:\\Chrome\\chrome.exe".into()),
            ),
            (
                10,
                "Chrome.exe".into(),
                Some("C:\\chrome\\CHROME.EXE".into()),
            ),
            (20, "svchost.exe".into(), None),
            (21, "svchost.exe".into(), None),
            (
                40,
                "chrome.exe".into(),
                Some("D:\\Portable\\chrome.exe".into()),
            ),
            (50, String::new(), None),
        ]
    }

    #[test]
    fn grouping() {
        let entries = group(raw());
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].pids, vec![10, 30], "same path in different case");
        assert_eq!(entries[1].path.as_deref(), Some("D:\\Portable\\chrome.exe"));
        assert_eq!(entries[2].pids, vec![20, 21]);
        assert_eq!(entries[2].pattern(), "svchost.exe");
        assert_eq!(entries[1].pattern(), "D:\\Portable\\chrome.exe");
    }

    #[test]
    fn filtering() {
        let entries = group(raw());
        assert_eq!(filter(&entries, "").len(), 3);
        assert_eq!(filter(&entries, "  CHROME ").len(), 2);
        assert_eq!(filter(&entries, "portable").len(), 1);
        assert!(filter(&entries, "zzz").is_empty());
    }

    #[test]
    fn live_snapshot_contains_this_process() {
        let me = std::process::id();
        assert!(snapshot().iter().any(|e| e.pids.contains(&me)));
    }
}
