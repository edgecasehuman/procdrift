use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessKey {
    pub pid: u32,
    pub created: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityKind {
    Started,
    Exited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEvent {
    pub at_seconds: u64,
    pub key: ProcessKey,
    pub executable: String,
    pub kind: ActivityKind,
}

#[derive(Default)]
pub struct ActivityTracker {
    live: HashMap<ProcessKey, String>,
    events: VecDeque<ActivityEvent>,
    starts: HashMap<String, VecDeque<u64>>,
    initialized: bool,
}

impl ActivityTracker {
    pub fn update(
        &mut self,
        now_seconds: u64,
        current: impl IntoIterator<Item = (ProcessKey, impl AsRef<str>)>,
    ) {
        let current: Vec<_> = current.into_iter().collect();
        if !self.initialized {
            self.live = current
                .into_iter()
                .map(|(key, executable)| (key, executable.as_ref().to_owned()))
                .collect();
            self.initialized = true;
            return;
        }
        let old_keys: HashSet<_> = self.live.keys().copied().collect();
        let new_keys: HashSet<_> = current.iter().map(|(key, _)| *key).collect();
        for key in new_keys.difference(&old_keys) {
            let executable = current
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, executable)| executable.as_ref().to_owned())
                .unwrap_or_default();
            self.events.push_back(ActivityEvent {
                at_seconds: now_seconds,
                key: *key,
                executable: executable.clone(),
                kind: ActivityKind::Started,
            });
            let starts = self.starts.entry(executable).or_default();
            starts.push_back(now_seconds);
            while starts.len() > 8 {
                starts.pop_front();
            }
        }
        for key in old_keys.difference(&new_keys) {
            self.events.push_back(ActivityEvent {
                at_seconds: now_seconds,
                key: *key,
                executable: self.live[key].clone(),
                kind: ActivityKind::Exited,
            });
        }
        self.live.retain(|key, _| new_keys.contains(key));
        for (key, executable) in current {
            self.live
                .entry(key)
                .or_insert_with(|| executable.as_ref().to_owned());
        }
        self.expire(now_seconds);
    }

    pub fn is_restarting(&self, executable: &str, now_seconds: u64) -> bool {
        self.starts.get(executable).is_some_and(|starts| {
            starts
                .iter()
                .filter(|started| now_seconds.saturating_sub(**started) <= 120)
                .count()
                >= 3
        })
    }

    pub fn events(&self) -> impl DoubleEndedIterator<Item = &ActivityEvent> {
        self.events.iter()
    }

    fn expire(&mut self, now_seconds: u64) {
        while self.events.front().is_some_and(|event| {
            self.events.len() > 128 || now_seconds.saturating_sub(event.at_seconds) > 600
        }) {
            self.events.pop_front();
        }
        self.starts.retain(|_, starts| {
            while starts
                .front()
                .is_some_and(|started| now_seconds.saturating_sub(*started) > 600)
            {
                starts.pop_front();
            }
            !starts.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: u32, created: u64) -> ProcessKey {
        ProcessKey { pid, created }
    }

    #[test]
    fn pid_reuse_is_an_exit_and_start_and_restart_threshold_is_three() {
        let mut tracker = ActivityTracker::default();
        tracker.update(0, [(key(10, 1), "app")]);
        tracker.update(30, [(key(10, 2), "app")]);
        tracker.update(60, [(key(10, 3), "app")]);
        tracker.update(90, [(key(10, 4), "app")]);
        assert!(tracker.is_restarting("app", 90));
        assert_eq!(tracker.events().count(), 6);
    }

    #[test]
    fn history_is_bounded_and_expires() {
        let mut tracker = ActivityTracker::default();
        for pid in 0..200 {
            tracker.update(pid.into(), [(key(pid, pid.into()), "app")]);
        }
        assert!(tracker.events().count() <= 128);
        tracker.update(1_000, std::iter::empty::<(ProcessKey, &str)>());
        assert!(tracker.events().count() <= 1);
    }

    #[test]
    fn initial_inventory_is_not_misreported_as_restart_activity() {
        let mut tracker = ActivityTracker::default();
        tracker.update(
            0,
            [
                (key(1, 1), "browser"),
                (key(2, 2), "browser"),
                (key(3, 3), "browser"),
            ],
        );
        assert!(!tracker.is_restarting("browser", 0));
        assert_eq!(tracker.events().count(), 0);
    }
}
