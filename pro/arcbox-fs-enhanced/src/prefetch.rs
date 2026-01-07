//! Intelligent prefetching.
//!
//! This module provides file access pattern learning and prediction.
//! It uses a combination of:
//! - Markov chain for sequential access patterns
//! - Frequency-based scoring for hot files
//! - Temporal locality for recent access patterns

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

/// Configuration for the prefetch engine.
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    /// Maximum number of transitions to track.
    pub max_transitions: usize,
    /// Maximum number of files to track frequency for.
    pub max_tracked_files: usize,
    /// Time window for recent access consideration.
    pub recent_window: Duration,
    /// Maximum suggestions to return.
    pub max_suggestions: usize,
    /// Minimum transition count to consider for prediction.
    pub min_transition_count: u32,
    /// Minimum access frequency to consider file "hot".
    pub min_hot_frequency: u32,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            max_transitions: 10000,
            max_tracked_files: 5000,
            recent_window: Duration::from_secs(60),
            max_suggestions: 10,
            min_transition_count: 3,
            min_hot_frequency: 5,
        }
    }
}

/// File access record.
#[derive(Debug, Clone)]
struct AccessRecord {
    /// Path of the accessed file.
    path: String,
    /// Timestamp of access.
    timestamp: Instant,
}

/// Transition statistics between files.
#[derive(Debug, Default)]
struct TransitionStats {
    /// Count of transitions to each target file.
    transitions: HashMap<String, u32>,
    /// Total transition count from this file.
    total: u32,
}

/// Prefetch engine.
///
/// Learns file access patterns and suggests files to prefetch based on:
/// - Sequential access patterns (file A is often followed by file B)
/// - Frequency-based patterns (frequently accessed files)
/// - Directory locality (files in recently accessed directories)
pub struct PrefetchEngine {
    /// Whether prefetching is enabled.
    enabled: bool,
    /// Configuration.
    config: PrefetchConfig,
    /// File access frequency counter.
    frequency: HashMap<String, u32>,
    /// Markov chain: transitions from file A to file B.
    /// Key is source file, value contains target file counts.
    transitions: HashMap<String, TransitionStats>,
    /// Recent access history for temporal locality.
    recent_accesses: VecDeque<AccessRecord>,
    /// Last accessed file (for tracking transitions).
    last_accessed: Option<String>,
    /// Directory access counts.
    directory_frequency: HashMap<String, u32>,
}

impl PrefetchEngine {
    /// Creates a new prefetch engine.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self::with_config(enabled, PrefetchConfig::default())
    }

    /// Creates a new prefetch engine with custom configuration.
    #[must_use]
    pub fn with_config(enabled: bool, config: PrefetchConfig) -> Self {
        Self {
            enabled,
            config,
            frequency: HashMap::new(),
            transitions: HashMap::new(),
            recent_accesses: VecDeque::new(),
            last_accessed: None,
            directory_frequency: HashMap::new(),
        }
    }

    /// Records a file access for learning.
    ///
    /// This updates:
    /// - File frequency counter
    /// - Transition probabilities (Markov chain)
    /// - Recent access history
    /// - Directory frequency
    pub fn record_access(&mut self, path: &str) {
        if !self.enabled {
            return;
        }

        let now = Instant::now();

        // Update file frequency.
        self.update_frequency(path);

        // Update directory frequency.
        self.update_directory_frequency(path);

        // Update transition from last file to this file.
        self.update_transition(path);

        // Add to recent access history.
        self.add_recent_access(path, now);

        // Update last accessed.
        self.last_accessed = Some(path.to_string());
    }

    /// Updates file access frequency.
    fn update_frequency(&mut self, path: &str) {
        // Evict least frequent if at capacity.
        if self.frequency.len() >= self.config.max_tracked_files
            && !self.frequency.contains_key(path)
        {
            self.evict_least_frequent();
        }

        *self.frequency.entry(path.to_string()).or_insert(0) += 1;
    }

    /// Updates directory access frequency.
    fn update_directory_frequency(&mut self, path: &str) {
        if let Some(parent) = Path::new(path).parent() {
            let dir = parent.to_string_lossy().to_string();
            *self.directory_frequency.entry(dir).or_insert(0) += 1;
        }
    }

    /// Updates transition statistics (Markov chain).
    fn update_transition(&mut self, to_path: &str) {
        // Clone to avoid borrow conflicts.
        let from_path = match &self.last_accessed {
            Some(path) => path.clone(),
            None => return,
        };

        // Don't track self-transitions.
        if from_path == to_path {
            return;
        }

        // Evict old transitions if at capacity.
        if self.transitions.len() >= self.config.max_transitions
            && !self.transitions.contains_key(&from_path)
        {
            self.evict_old_transitions();
        }

        let stats = self
            .transitions
            .entry(from_path)
            .or_insert_with(TransitionStats::default);

        *stats.transitions.entry(to_path.to_string()).or_insert(0) += 1;
        stats.total += 1;
    }

    /// Adds an access to recent history.
    fn add_recent_access(&mut self, path: &str, timestamp: Instant) {
        // Remove stale entries.
        while let Some(front) = self.recent_accesses.front() {
            if timestamp.duration_since(front.timestamp) > self.config.recent_window {
                self.recent_accesses.pop_front();
            } else {
                break;
            }
        }

        self.recent_accesses.push_back(AccessRecord {
            path: path.to_string(),
            timestamp,
        });
    }

    /// Evicts the least frequent file from tracking.
    fn evict_least_frequent(&mut self) {
        if let Some(min_key) = self
            .frequency
            .iter()
            .min_by_key(|entry| *entry.1)
            .map(|(k, _)| k.clone())
        {
            self.frequency.remove(&min_key);
        }
    }

    /// Evicts old transitions to make room.
    fn evict_old_transitions(&mut self) {
        // Remove the transition source with lowest total count.
        if let Some(min_key) = self
            .transitions
            .iter()
            .min_by_key(|(_, stats)| stats.total)
            .map(|(k, _)| k.clone())
        {
            self.transitions.remove(&min_key);
        }
    }

    /// Suggests files to prefetch based on learned patterns.
    ///
    /// Returns a list of file paths that are likely to be accessed next,
    /// sorted by prediction confidence.
    #[must_use]
    pub fn suggest(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let mut scores: HashMap<String, f64> = HashMap::new();

        // Score based on Markov chain predictions.
        self.score_from_transitions(&mut scores);

        // Score based on frequency (hot files).
        self.score_from_frequency(&mut scores);

        // Score based on directory locality.
        self.score_from_directory_locality(&mut scores);

        // Sort by score and return top suggestions.
        let mut suggestions: Vec<_> = scores.into_iter().collect();
        suggestions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        suggestions
            .into_iter()
            .take(self.config.max_suggestions)
            .map(|(path, _)| path)
            .collect()
    }

    /// Scores files based on transition probabilities from current file.
    fn score_from_transitions(&self, scores: &mut HashMap<String, f64>) {
        if let Some(last) = &self.last_accessed {
            if let Some(stats) = self.transitions.get(last) {
                for (target, &count) in &stats.transitions {
                    if count >= self.config.min_transition_count {
                        // Probability-based score (higher weight).
                        let prob = count as f64 / stats.total as f64;
                        *scores.entry(target.clone()).or_insert(0.0) += prob * 10.0;
                    }
                }
            }
        }
    }

    /// Scores files based on access frequency.
    fn score_from_frequency(&self, scores: &mut HashMap<String, f64>) {
        let max_freq = self.frequency.values().copied().max().unwrap_or(1) as f64;

        for (path, &count) in &self.frequency {
            if count >= self.config.min_hot_frequency {
                // Skip the last accessed file.
                if self.last_accessed.as_ref() == Some(path) {
                    continue;
                }
                // Normalized frequency score.
                let score = (count as f64 / max_freq) * 3.0;
                *scores.entry(path.clone()).or_insert(0.0) += score;
            }
        }
    }

    /// Scores files based on directory locality.
    fn score_from_directory_locality(&self, scores: &mut HashMap<String, f64>) {
        // Find directories with recent activity.
        let mut recent_dirs: HashMap<String, u32> = HashMap::new();
        for record in &self.recent_accesses {
            if let Some(parent) = Path::new(&record.path).parent() {
                let dir = parent.to_string_lossy().to_string();
                *recent_dirs.entry(dir).or_insert(0) += 1;
            }
        }

        // Boost scores for files in recently accessed directories.
        for (path, freq_score) in scores.iter_mut() {
            if let Some(parent) = Path::new(path).parent() {
                let dir = parent.to_string_lossy().to_string();
                if let Some(&dir_count) = recent_dirs.get(&dir) {
                    // Small boost based on directory activity.
                    *freq_score += (dir_count as f64).ln() * 0.5;
                }
            }
        }
    }

    /// Returns the current access frequency for a file.
    #[must_use]
    pub fn get_frequency(&self, path: &str) -> u32 {
        self.frequency.get(path).copied().unwrap_or(0)
    }

    /// Returns the number of tracked files.
    #[must_use]
    pub fn tracked_file_count(&self) -> usize {
        self.frequency.len()
    }

    /// Returns the number of tracked transitions.
    #[must_use]
    pub fn tracked_transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Clears all learned patterns.
    pub fn clear(&mut self) {
        self.frequency.clear();
        self.transitions.clear();
        self.recent_accesses.clear();
        self.last_accessed = None;
        self.directory_frequency.clear();
    }

    /// Returns statistics about the prefetch engine.
    #[must_use]
    pub fn stats(&self) -> PrefetchStats {
        PrefetchStats {
            tracked_files: self.frequency.len(),
            tracked_transitions: self.transitions.len(),
            recent_accesses: self.recent_accesses.len(),
            total_accesses: self.frequency.values().sum(),
        }
    }
}

impl Default for PrefetchEngine {
    fn default() -> Self {
        Self::new(true)
    }
}

/// Statistics about the prefetch engine.
#[derive(Debug, Clone)]
pub struct PrefetchStats {
    /// Number of tracked files.
    pub tracked_files: usize,
    /// Number of tracked transitions.
    pub tracked_transitions: usize,
    /// Number of recent accesses in the window.
    pub recent_accesses: usize,
    /// Total access count.
    pub total_accesses: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefetch_disabled() {
        let mut engine = PrefetchEngine::new(false);
        engine.record_access("/foo/bar.txt");
        assert!(engine.suggest().is_empty());
        assert_eq!(engine.get_frequency("/foo/bar.txt"), 0);
    }

    #[test]
    fn test_frequency_tracking() {
        let mut engine = PrefetchEngine::new(true);

        engine.record_access("/foo/a.txt");
        engine.record_access("/foo/a.txt");
        engine.record_access("/foo/b.txt");

        assert_eq!(engine.get_frequency("/foo/a.txt"), 2);
        assert_eq!(engine.get_frequency("/foo/b.txt"), 1);
        assert_eq!(engine.tracked_file_count(), 2);
    }

    #[test]
    fn test_transition_tracking() {
        // Use lower thresholds for testing.
        let config = PrefetchConfig {
            min_transition_count: 2,
            min_hot_frequency: 2,
            ..Default::default()
        };
        let mut engine = PrefetchEngine::with_config(true, config);

        // Access pattern: a -> b -> c -> a -> b -> c -> a -> b -> c
        for _ in 0..3 {
            engine.record_access("/foo/a.txt");
            engine.record_access("/foo/b.txt");
            engine.record_access("/foo/c.txt");
        }

        // After c.txt, a.txt should be suggested (2+ transitions c->a).
        let suggestions = engine.suggest();
        assert!(!suggestions.is_empty(), "Expected non-empty suggestions");
        // a.txt should be in suggestions due to high transition probability.
        assert!(
            suggestions.contains(&"/foo/a.txt".to_string()),
            "Expected /foo/a.txt in suggestions: {:?}",
            suggestions
        );
    }

    #[test]
    fn test_hot_file_suggestion() {
        let config = PrefetchConfig {
            min_hot_frequency: 3,
            ..Default::default()
        };
        let mut engine = PrefetchEngine::with_config(true, config);

        // Make one file very hot.
        for _ in 0..10 {
            engine.record_access("/hot/file.txt");
        }
        engine.record_access("/other/file.txt");

        let suggestions = engine.suggest();
        // Hot file should be suggested.
        assert!(
            suggestions.contains(&"/hot/file.txt".to_string()),
            "Expected /hot/file.txt in suggestions: {:?}",
            suggestions
        );
    }

    #[test]
    fn test_clear() {
        let mut engine = PrefetchEngine::new(true);

        engine.record_access("/foo/a.txt");
        engine.record_access("/foo/b.txt");

        assert_eq!(engine.tracked_file_count(), 2);

        engine.clear();

        assert_eq!(engine.tracked_file_count(), 0);
        assert_eq!(engine.tracked_transition_count(), 0);
    }

    #[test]
    fn test_stats() {
        let mut engine = PrefetchEngine::new(true);

        engine.record_access("/foo/a.txt");
        engine.record_access("/foo/b.txt");
        engine.record_access("/foo/a.txt");

        let stats = engine.stats();
        assert_eq!(stats.tracked_files, 2);
        assert_eq!(stats.total_accesses, 3);
    }
}
