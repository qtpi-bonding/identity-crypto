//! Replay protection: remembers `(session key, nonce)` pairs for as long as a
//! message carrying that nonce could still pass the skew check. Lifted from an
//! existing in-house replay cache; the clock is now a parameter of every call,
//! so the cache holds no time source of its own.

use identity_crypto::PublicKey;
pub use identity_crypto::SKEW_SECONDS;
use std::collections::HashMap;

/// Extra retention after an entry's skew window closes, so that a message
/// verified just before the window closed cannot race the purge.
pub const PURGE_GRACE: i64 = 30;

/// Limits on live entries. A full cache refuses new entries; it never evicts.
#[derive(Clone, Copy, Debug)]
pub struct NonceCaps {
    pub per_key: usize,
    pub total: usize,
}

impl Default for NonceCaps {
    fn default() -> Self {
        Self {
            per_key: 256,
            total: 4096,
        }
    }
}

/// The outcome of [`NonceCache::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// First sighting: the entry is stored.
    Fresh,
    /// Seen before and still retained: refuse the message.
    Replayed,
    /// A cap is reached: refuse the message, evict nothing.
    Busy,
}

/// Replay cache keyed by session key and nonce.
#[derive(Debug)]
pub struct NonceCache {
    entries: HashMap<(Vec<u8>, Vec<u8>), i64>,
    counts: HashMap<Vec<u8>, usize>,
    caps: NonceCaps,
}

impl NonceCache {
    pub fn new(caps: NonceCaps) -> Self {
        Self {
            entries: HashMap::new(),
            counts: HashMap::new(),
            caps,
        }
    }

    /// Records `nonce` under `session_key` if it is fresh. `issued_at` is the
    /// message's own timestamp and `now` the clock at this check; the entry is
    /// kept until `issued_at + SKEW_SECONDS + PURGE_GRACE` has passed.
    pub fn insert(
        &mut self,
        session_key: &PublicKey,
        nonce: &[u8],
        issued_at: i64,
        now: i64,
    ) -> Insert {
        self.purge(now);
        let key = session_key.as_bytes().to_vec();
        let mapkey = (key.clone(), nonce.to_vec());
        if self.entries.contains_key(&mapkey) {
            return Insert::Replayed;
        }
        if self.entries.len() >= self.caps.total
            || self.counts.get(&key).copied().unwrap_or(0) >= self.caps.per_key
        {
            return Insert::Busy;
        }
        self.entries.insert(mapkey, issued_at + SKEW_SECONDS);
        *self.counts.entry(key).or_default() += 1;
        Insert::Fresh
    }

    fn purge(&mut self, now: i64) {
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, expiry)| **expiry + PURGE_GRACE < now)
            .map(|(k, _)| k.clone())
            .collect();
        for (key, nonce) in removed {
            self.entries.remove(&(key.clone(), nonce));
            if let Some(count) = self.counts.get_mut(&key) {
                *count -= 1;
                if *count == 0 {
                    self.counts.remove(&key);
                }
            }
        }
    }

    /// Live entries, for tests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_crypto::jwk_duo::SigningKeyPair;

    fn key() -> PublicKey {
        PublicKey::from(&SigningKeyPair::generate())
    }

    #[test]
    fn a_nonce_is_fresh_once_then_replayed() {
        let (k, mut cache) = (key(), NonceCache::new(NonceCaps::default()));
        assert_eq!(cache.insert(&k, b"n1", 100, 100), Insert::Fresh);
        assert_eq!(cache.insert(&k, b"n1", 100, 100), Insert::Replayed);
        assert_eq!(cache.insert(&key(), b"n1", 100, 100), Insert::Fresh);
    }

    #[test]
    fn an_entry_blocks_through_the_grace_and_is_gone_after() {
        let (k, mut cache) = (key(), NonceCache::new(NonceCaps::default()));
        assert_eq!(cache.insert(&k, b"n1", 100, 100), Insert::Fresh);
        // expiry = 130; a replay is refused at exactly issued_at + 30...
        assert_eq!(cache.insert(&k, b"n1", 100, 130), Insert::Replayed);
        // ...and still at issued_at + 60 (the purge grace)...
        assert_eq!(cache.insert(&k, b"n1", 100, 160), Insert::Replayed);
        assert_eq!(cache.len(), 1);
        // ...and purged by an insert at issued_at + 61.
        assert_eq!(cache.insert(&k, b"n2", 161, 161), Insert::Fresh);
        assert_eq!(cache.len(), 1, "n1 was purged, n2 stored");
    }

    #[test]
    fn a_verification_snapshot_racing_the_actor_cannot_reopen_a_replay() {
        // A verified at now=130 reaches the cache after B (checked at 131).
        let (k, mut cache) = (key(), NonceCache::new(NonceCaps::default()));
        assert_eq!(cache.insert(&k, b"a", 100, 130), Insert::Fresh);
        assert_eq!(cache.insert(&key(), b"b", 131, 131), Insert::Fresh);
        assert_eq!(cache.insert(&k, b"a", 100, 130), Insert::Replayed);
    }

    #[test]
    fn the_caps_refuse_and_never_evict() {
        let mut cache = NonceCache::new(NonceCaps {
            per_key: 3,
            total: 5,
        });
        let (a, b, c) = (key(), key(), key());
        for n in [b"1", b"2", b"3"] {
            assert_eq!(cache.insert(&a, n, 100, 100), Insert::Fresh);
        }
        assert_eq!(cache.insert(&a, b"4", 100, 100), Insert::Busy);
        assert_eq!(
            cache.insert(&a, b"1", 100, 100),
            Insert::Replayed,
            "nothing evicted"
        );
        // One agent at its cap does not block another.
        assert_eq!(cache.insert(&b, b"1", 100, 100), Insert::Fresh);
        assert_eq!(cache.insert(&b, b"2", 100, 100), Insert::Fresh);
        // The total cap (5) refuses the sixth entry overall.
        assert_eq!(cache.insert(&c, b"1", 100, 100), Insert::Busy);
        assert_eq!(cache.len(), 5);
    }
}
