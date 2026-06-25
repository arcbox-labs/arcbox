use std::time::{Duration, Instant};

use hickory_proto::op::Message as DnsMessage;

use super::{DnsClass, DnsForwarder, DnsQuery, DnsRecordType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct DnsCacheKey {
    name: String,
    qtype: DnsRecordType,
    qclass: DnsClass,
}

impl DnsCacheKey {
    pub(super) fn new(name: &str, qtype: DnsRecordType, qclass: DnsClass) -> Self {
        Self {
            name: name.to_lowercase(),
            qtype,
            qclass,
        }
    }
}

/// DNS cache entry.
#[derive(Debug, Clone)]
pub(super) struct CacheEntry {
    /// Complete upstream response bytes with the original transaction ID.
    response: Vec<u8>,
    /// When the entry was cached.
    cached_at: Instant,
    /// TTL from the response.
    pub(super) ttl: Duration,
}

impl CacheEntry {
    /// Checks if the entry is expired.
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() >= self.ttl
    }
}

impl DnsForwarder {
    /// Checks the cache for a query.
    pub(super) fn check_cache(&mut self, query: &DnsQuery) -> Option<Vec<u8>> {
        let key = DnsCacheKey::new(&query.name, query.qtype, query.qclass);

        // Clean up expired entries.
        self.cache.retain(|_, v| !v.is_expired());

        self.cache.get(&key).map(|entry| {
            let mut response = entry.response.clone();
            response[0..2].copy_from_slice(&query.raw_header[0..2]);
            response
        })
    }

    /// Caches a validated upstream DNS response.
    ///
    /// The cache stores the complete wire response and only rewrites the
    /// transaction ID on hits. That preserves DNS compression pointers,
    /// authority/additional sections, EDNS, DNSSEC, and record-type-specific
    /// RDATA without maintaining a fragile local packet re-builder. Hickory
    /// parses the response only to validate it and derive a safe expiry TTL.
    pub(super) fn cache_response(&mut self, query: &DnsQuery, response: &[u8]) {
        let Some(ttl) = self.cache_ttl_for_response(response) else {
            return;
        };

        let key = DnsCacheKey::new(&query.name, query.qtype, query.qclass);
        let entry = CacheEntry {
            response: response.to_vec(),
            cached_at: Instant::now(),
            ttl,
        };
        self.cache.insert(key, entry);
    }

    fn cache_ttl_for_response(&self, response: &[u8]) -> Option<Duration> {
        let message = DnsMessage::from_vec(response).ok()?;
        let min_answer_ttl = message.answers.iter().map(|record| record.ttl).min()?;
        if min_answer_ttl == 0 || self.config.cache_ttl.is_zero() {
            return None;
        }
        Some(Duration::from_secs(u64::from(min_answer_ttl)).min(self.config.cache_ttl))
    }
}
