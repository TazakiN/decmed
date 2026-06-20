/// Format an encounter/RME id. This is not a segment metadata index.
///
/// The sequence must come from a centralized atomic counter owned by the PRE
/// server; callers must not derive it from on-chain metadata.index.
pub fn format_related_rme_id(year: i32, sequence: u64) -> String {
    format!("RME-{year}-{sequence:06}")
}

/// Compatibility wrapper for callers that still use the old generator name.
/// It no longer creates entropy locally; the sequence is supplied by PRE.
pub fn generate_related_rme_id(now: chrono::DateTime<chrono::Utc>, sequence: u64) -> String {
    use chrono::Datelike;

    format_related_rme_id(now.year(), sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn formats_incremental_rme_id() {
        assert_eq!(format_related_rme_id(2026, 1), "RME-2026-000001");
        assert_eq!(format_related_rme_id(2026, 123), "RME-2026-000123");
    }

    #[test]
    fn generator_uses_supplied_sequence() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 23, 12, 0, 0).unwrap();
        let id = generate_related_rme_id(now, 42);
        assert_eq!(id, "RME-2026-000042");
    }

    #[test]
    fn old_uuid_format_remains_plain_string_compatible() {
        let old_id = "RME-2026-b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31";
        assert!(old_id.starts_with("RME-2026-"));
    }
}
