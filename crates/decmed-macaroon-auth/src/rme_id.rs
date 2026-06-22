/// Format an encounter/RME id. This is not a segment metadata index.
///
/// The sequence must come from a centralized atomic counter owned by the PRE
/// server; callers must not derive it from on-chain metadata.index.
pub fn format_related_rme_id(sequence: u64) -> String {
    format!("RME-{sequence:06}")
}

/// Wrapper for callers that still use the generator name.
/// It no longer creates entropy locally; the sequence is supplied by PRE.
pub fn generate_related_rme_id(_now: chrono::DateTime<chrono::Utc>, sequence: u64) -> String {
    format_related_rme_id(sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn formats_incremental_rme_id() {
        assert_eq!(format_related_rme_id(1), "RME-000001");
        assert_eq!(format_related_rme_id(123), "RME-000123");
    }

    #[test]
    fn generator_uses_supplied_sequence() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 23, 12, 0, 0).unwrap();
        let id = generate_related_rme_id(now, 42);
        assert_eq!(id, "RME-000042");
    }
}
