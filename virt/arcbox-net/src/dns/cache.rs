use std::time::{Duration, Instant};

use hickory_proto::op::Message as DnsMessage;

use super::{DnsClass, DnsForwarder, DnsQuery, DnsRecordType};

const DNS_HEADER_LEN: usize = 12;
const TYPE_OPT: u16 = 41;

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
    pub(super) cached_at: Instant,
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

        self.cache.get(&key).and_then(|entry| {
            let mut response = entry.response.clone();
            response[0..2].copy_from_slice(&query.raw_header[0..2]);
            rewrite_question(&mut response, &query.raw_question)?;
            rewrite_ttls(
                &mut response,
                entry
                    .ttl
                    .as_secs()
                    .saturating_sub(entry.cached_at.elapsed().as_secs()),
            )?;
            Some(response)
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

fn rewrite_question(response: &mut [u8], raw_question: &[u8]) -> Option<()> {
    let question_end = skip_questions(response, DNS_HEADER_LEN, 1)?;
    if question_end != DNS_HEADER_LEN + raw_question.len() {
        return None;
    }
    response[DNS_HEADER_LEN..question_end].copy_from_slice(raw_question);
    Some(())
}

fn rewrite_ttls(response: &mut [u8], remaining_ttl_secs: u64) -> Option<()> {
    let qdcount = read_count(response, 4)?;
    let ancount = read_count(response, 6)?;
    let nscount = read_count(response, 8)?;
    let arcount = read_count(response, 10)?;

    let mut offset = skip_questions(response, DNS_HEADER_LEN, qdcount)?;
    let remaining_secs = remaining_ttl_secs.min(u64::from(u32::MAX)) as u32;
    let total_records = u32::from(ancount) + u32::from(nscount) + u32::from(arcount);
    for _ in 0..total_records {
        offset = rewrite_record_ttl(response, offset, remaining_secs)?;
    }
    Some(())
}

fn read_count(response: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *response.get(offset)?,
        *response.get(offset + 1)?,
    ]))
}

fn skip_questions(response: &[u8], mut offset: usize, count: u16) -> Option<usize> {
    for _ in 0..count {
        offset = skip_name(response, offset)?;
        offset = offset.checked_add(4)?;
        if offset > response.len() {
            return None;
        }
    }
    Some(offset)
}

fn skip_name(response: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *response.get(offset)?;
        if len & 0xC0 == 0xC0 {
            return offset.checked_add(2).filter(|end| *end <= response.len());
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset = offset.checked_add(1)?;
        if len == 0 {
            return Some(offset);
        }
        offset = offset.checked_add(usize::from(len))?;
        if offset > response.len() {
            return None;
        }
    }
}

fn rewrite_record_ttl(response: &mut [u8], offset: usize, remaining_secs: u32) -> Option<usize> {
    let record_header = skip_name(response, offset)?;
    let record_type = u16::from_be_bytes([
        *response.get(record_header)?,
        *response.get(record_header + 1)?,
    ]);
    let ttl_offset = record_header.checked_add(4)?;
    let rdlength_offset = record_header.checked_add(8)?;
    let rdlength = u16::from_be_bytes([
        *response.get(rdlength_offset)?,
        *response.get(rdlength_offset + 1)?,
    ]);
    let rdata_offset = record_header.checked_add(10)?;
    let next_record = rdata_offset.checked_add(usize::from(rdlength))?;
    if next_record > response.len() {
        return None;
    }

    if record_type != TYPE_OPT {
        let original_ttl = u32::from_be_bytes([
            *response.get(ttl_offset)?,
            *response.get(ttl_offset + 1)?,
            *response.get(ttl_offset + 2)?,
            *response.get(ttl_offset + 3)?,
        ]);
        let ttl = original_ttl.min(remaining_secs);
        response[ttl_offset..ttl_offset + 4].copy_from_slice(&ttl.to_be_bytes());
    }

    Some(next_record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_ttls_rejects_record_count_sum_above_u16_max() {
        let mut response = vec![0; DNS_HEADER_LEN];
        response[4..6].copy_from_slice(&1u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response[8..10].copy_from_slice(&u16::MAX.to_be_bytes());

        response.push(0);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        response.extend_from_slice(&0xC00Cu16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 1]);

        assert!(rewrite_ttls(&mut response, 30).is_none());
    }
}
