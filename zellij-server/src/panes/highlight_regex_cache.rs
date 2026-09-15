//! Process-wide interning of compiled plugin highlight regexes.
//!
//! Plugins (e.g. the default `zellij:link` plugin) register the same patterns on
//! every terminal pane. A compiled `Regex` carries its program plus a lazy DFA
//! cache, so compiling it per pane costs megabytes per pane. Instead, every
//! `CompiledHighlight` holds an `Arc<Regex>` handed out by this cache.
//!
//! The cache only keeps `Weak` references: a regex is freed as soon as the last
//! highlight using it is dropped (the plugin clears or replaces its highlights,
//! the plugin unloads, or the pane closes), so dynamically generated patterns
//! don't accumulate. Dead entries are pruned whenever the map has doubled in
//! size since the last prune, which keeps inserts amortized O(1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

const MIN_PRUNE_THRESHOLD: usize = 64;

pub struct HighlightRegexCache {
    regexes: HashMap<String, Weak<regex::Regex>>,
    prune_threshold: usize,
}

impl Default for HighlightRegexCache {
    fn default() -> Self {
        HighlightRegexCache {
            regexes: HashMap::new(),
            prune_threshold: MIN_PRUNE_THRESHOLD,
        }
    }
}

impl HighlightRegexCache {
    /// Returns the live compiled regex for `pattern`, compiling it if no pane
    /// currently holds one.
    pub fn get_or_compile(&mut self, pattern: &str) -> Result<Arc<regex::Regex>, regex::Error> {
        if let Some(regex) = self.regexes.get(pattern).and_then(Weak::upgrade) {
            return Ok(regex);
        }
        let regex = Arc::new(regex::Regex::new(pattern)?);
        self.regexes.insert(pattern.to_owned(), Arc::downgrade(&regex));
        if self.regexes.len() >= self.prune_threshold {
            self.prune();
        }
        Ok(regex)
    }

    fn prune(&mut self) {
        self.regexes.retain(|_, regex| regex.strong_count() > 0);
        self.prune_threshold = (self.regexes.len() * 2).max(MIN_PRUNE_THRESHOLD);
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.regexes.len()
    }

    #[cfg(test)]
    pub fn is_live(&self, pattern: &str) -> bool {
        self.regexes
            .get(pattern)
            .map(|regex| regex.strong_count() > 0)
            .unwrap_or(false)
    }
}

fn global_cache() -> &'static Mutex<HighlightRegexCache> {
    static CACHE: OnceLock<Mutex<HighlightRegexCache>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Compile `pattern` or share the already compiled regex with other panes.
pub fn shared_highlight_regex(pattern: &str) -> Result<Arc<regex::Regex>, regex::Error> {
    global_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_compile(pattern)
}

#[cfg(test)]
pub fn shared_highlight_regex_is_live(pattern: &str) -> bool {
    global_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_live(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_pattern_shares_compiled_regex() {
        let mut cache = HighlightRegexCache::default();
        let first = cache.get_or_compile("foo").unwrap();
        let second = cache.get_or_compile("foo").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let other = cache.get_or_compile("bar").unwrap();
        assert!(!Arc::ptr_eq(&first, &other));
    }

    #[test]
    fn regex_is_freed_when_last_user_drops_it() {
        let mut cache = HighlightRegexCache::default();
        let first = cache.get_or_compile("foo").unwrap();
        let second = cache.get_or_compile("foo").unwrap();
        drop(first);
        assert!(cache.is_live("foo"));
        let weak = Arc::downgrade(&second);
        drop(second);
        assert!(!cache.is_live("foo"));
        assert!(weak.upgrade().is_none());
        // recompiled on demand after being freed
        let recompiled = cache.get_or_compile("foo").unwrap();
        assert!(recompiled.is_match("foo"));
        assert!(cache.is_live("foo"));
    }

    #[test]
    fn invalid_pattern_is_not_cached() {
        let mut cache = HighlightRegexCache::default();
        assert!(cache.get_or_compile("(unclosed").is_err());
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn dead_entries_are_pruned() {
        let mut cache = HighlightRegexCache::default();
        let kept: Vec<_> = (0..10)
            .map(|i| cache.get_or_compile(&format!("kept{}", i)).unwrap())
            .collect();
        // simulate a plugin churning through dynamic patterns that are
        // immediately released (e.g. directory entries on every cd)
        for i in 0..10_000 {
            drop(cache.get_or_compile(&format!("dynamic{}", i)).unwrap());
            assert!(cache.entry_count() < MIN_PRUNE_THRESHOLD);
        }
        for (i, regex) in kept.iter().enumerate() {
            let pattern = format!("kept{}", i);
            assert!(cache.is_live(&pattern));
            assert!(Arc::ptr_eq(regex, &cache.get_or_compile(&pattern).unwrap()));
        }
    }

    #[test]
    fn prune_threshold_scales_with_live_entries() {
        let mut cache = HighlightRegexCache::default();
        let kept: Vec<_> = (0..200)
            .map(|i| cache.get_or_compile(&format!("kept{}", i)).unwrap())
            .collect();
        for i in 0..1_000 {
            drop(cache.get_or_compile(&format!("dynamic{}", i)).unwrap());
            // the regex being returned is still alive while pruning
            assert!(cache.entry_count() <= (kept.len() + 1) * 2);
        }
    }
}
