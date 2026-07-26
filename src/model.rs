use std::collections::{HashMap, HashSet};

pub const CPU_HEAVY_TENTHS: u32 = 10;
pub const MEMORY_HEAVY_BYTES: u64 = 128 * 1024 * 1024;
pub const DISK_HEAVY_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustState {
    Protected,
    Allowed,
    Known,
    Unclassified,
}

impl TrustState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Protected => "Protected",
            Self::Allowed => "Allowed",
            Self::Known => "Known",
            Self::Unclassified => "Unclassified",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Findings(u16);

impl Findings {
    pub const NEW: u16 = 1 << 0;
    pub const DIFFERENT_PATH: u16 = 1 << 1;
    pub const PARENT_ENDED: u16 = 1 << 2;
    pub const HEAVY_CPU: u16 = 1 << 3;
    pub const HEAVY_MEMORY: u16 = 1 << 4;
    pub const HEAVY_DISK: u16 = 1 << 5;
    pub const PEER_OUTLIER: u16 = 1 << 6;
    pub const RESTARTING: u16 = 1 << 7;
    pub const MANY_INSTANCES: u16 = 1 << 8;
    pub const LAUNCHED_BY_KNOWN: u16 = 1 << 9;
    pub const STARTS_AUTOMATICALLY: u16 = 1 << 10;

    /// True when *any* bit in `finding` is set. Callers pass several flags at
    /// once to ask "any of these", which is why this is an intersection test
    /// rather than a subset test.
    pub const fn contains(self, finding: u16) -> bool {
        self.0 & finding != 0
    }

    pub fn insert(&mut self, finding: u16) {
        self.0 |= finding;
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn calm_reasons(self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        for (flag, reason) in [
            (Self::NEW, "Not present in the reference snapshot"),
            (
                Self::DIFFERENT_PATH,
                "This name was seen at a different path",
            ),
            (
                Self::PARENT_ENDED,
                "The launching process is no longer running",
            ),
            (Self::HEAVY_CPU, "Currently among the highest CPU users"),
            (
                Self::HEAVY_MEMORY,
                "Currently among the highest memory users",
            ),
            (Self::HEAVY_DISK, "Currently among the highest disk users"),
            (
                Self::PEER_OUTLIER,
                "Using more resources than matching instances",
            ),
            (
                Self::RESTARTING,
                "Started at least three times in two minutes",
            ),
            (
                Self::MANY_INSTANCES,
                "Multiple matching instances are running",
            ),
            (Self::LAUNCHED_BY_KNOWN, "Launched by a known process"),
            (
                Self::STARTS_AUTOMATICALLY,
                "An exact startup entry was found",
            ),
        ] {
            if self.contains(flag) {
                reasons.push(reason);
            }
        }
        reasons
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Filter {
    Review,
    New,
    Heavy,
    Restarting,
    Known,
    All,
}

#[derive(Clone, Debug)]
pub struct EvidenceRow {
    pub trust: TrustState,
    pub findings: Findings,
    pub cpu_tenths: u32,
    pub memory_bytes: u64,
    pub disk_bytes_per_second: u64,
}

impl EvidenceRow {
    pub fn matches_filter(&self, filter: Filter) -> bool {
        let heavy = self
            .findings
            .contains(Findings::HEAVY_CPU | Findings::HEAVY_MEMORY | Findings::HEAVY_DISK);
        match filter {
            Filter::Review => {
                // A new executable that also has a startup entry survives a
                // reboot, so it belongs in review even when its trust state
                // would not otherwise put it there.
                let persistent_and_new = self.findings.contains(Findings::NEW)
                    && self.findings.contains(Findings::STARTS_AUTOMATICALLY);
                self.trust == TrustState::Unclassified
                    || persistent_and_new
                    || self.findings.contains(
                        Findings::DIFFERENT_PATH
                            | Findings::PARENT_ENDED
                            | Findings::RESTARTING
                            | Findings::PEER_OUTLIER,
                    )
                    || heavy
            }
            Filter::New => self
                .findings
                .contains(Findings::NEW | Findings::DIFFERENT_PATH),
            Filter::Heavy => heavy,
            Filter::Restarting => self.findings.contains(Findings::RESTARTING),
            Filter::Known => matches!(self.trust, TrustState::Known | TrustState::Allowed),
            Filter::All => true,
        }
    }
}

pub fn apply_resource_findings(rows: &mut [EvidenceRow]) {
    mark_top_five(
        rows,
        |row| row.cpu_tenths,
        CPU_HEAVY_TENTHS,
        Findings::HEAVY_CPU,
    );
    mark_top_five(
        rows,
        |row| row.memory_bytes,
        MEMORY_HEAVY_BYTES,
        Findings::HEAVY_MEMORY,
    );
    mark_top_five(
        rows,
        |row| row.disk_bytes_per_second,
        DISK_HEAVY_BYTES,
        Findings::HEAVY_DISK,
    );
}

fn mark_top_five<T: Ord + Copy>(
    rows: &mut [EvidenceRow],
    value: impl Fn(&EvidenceRow) -> T,
    minimum: T,
    flag: u16,
) {
    let mut ranked: Vec<(usize, T)> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            let measured = value(row);
            (measured >= minimum).then_some((index, measured))
        })
        .collect();
    ranked.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));
    for (index, _) in ranked.into_iter().take(5) {
        rows[index].findings.insert(flag);
    }
}

pub fn peer_outliers<K>(samples: &HashMap<K, Vec<(usize, u32, u64)>>) -> HashSet<usize> {
    let mut outliers = HashSet::new();
    for peers in samples.values().filter(|peers| peers.len() >= 3) {
        let cpu: Vec<u64> = peers.iter().map(|sample| u64::from(sample.1)).collect();
        let memory: Vec<u64> = peers.iter().map(|sample| sample.2).collect();
        let cpu_limit = robust_limit(&cpu, 30);
        let memory_limit = robust_limit(&memory, MEMORY_HEAVY_BYTES);
        for (index, cpu, memory) in peers {
            if u64::from(*cpu) > cpu_limit || *memory > memory_limit {
                outliers.insert(*index);
            }
        }
    }
    outliers
}

fn robust_limit(values: &[u64], floor_delta: u64) -> u64 {
    let midpoint = median(values);
    let deviations: Vec<u64> = values
        .iter()
        .map(|value| value.abs_diff(midpoint))
        .collect();
    midpoint.saturating_add((median(&deviations).saturating_mul(4)).max(floor_delta))
}

fn median(values: &[u64]) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cpu: u32, memory: u64, disk: u64) -> EvidenceRow {
        EvidenceRow {
            trust: TrustState::Unclassified,
            findings: Findings::default(),
            cpu_tenths: cpu,
            memory_bytes: memory,
            disk_bytes_per_second: disk,
        }
    }

    #[test]
    fn trust_and_findings_are_independent_and_explanations_are_calm() {
        let mut findings = Findings::default();
        findings.insert(Findings::PARENT_ENDED | Findings::HEAVY_CPU);
        assert_eq!(TrustState::Known.label(), "Known");
        assert_eq!(
            findings.calm_reasons(),
            [
                "The launching process is no longer running",
                "Currently among the highest CPU users"
            ]
        );
        assert!(
            findings
                .calm_reasons()
                .iter()
                .all(|reason| { !reason.contains("malicious") && !reason.contains("threat") })
        );
    }

    #[test]
    fn leaderboard_honors_minimums_and_five_item_bound() {
        let mut rows: Vec<_> = (0..9).map(|i| row(10 + i, 0, 0)).collect();
        rows.push(row(9, MEMORY_HEAVY_BYTES - 1, DISK_HEAVY_BYTES - 1));
        apply_resource_findings(&mut rows);
        assert_eq!(
            rows.iter()
                .filter(|row| row.findings.contains(Findings::HEAVY_CPU))
                .count(),
            5
        );
        assert!(
            !rows[9]
                .findings
                .contains(Findings::HEAVY_CPU | Findings::HEAVY_MEMORY | Findings::HEAVY_DISK)
        );
    }

    #[test]
    fn peer_outlier_requires_three_exact_path_peers_and_robust_threshold() {
        let samples: HashMap<String, Vec<(usize, u32, u64)>> = HashMap::from([
            ("a".into(), vec![(0, 10, 10), (1, 11, 11), (2, 80, 12)]),
            ("b".into(), vec![(3, 1, 1), (4, 999, u64::MAX)]),
        ]);
        assert_eq!(peer_outliers(&samples), HashSet::from([2]));
    }
}
