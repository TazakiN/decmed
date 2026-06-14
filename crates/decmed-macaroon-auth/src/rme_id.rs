use uuid::Uuid;

/// Generate a new related RME id for an admin delegation episode.
/// Format: `RME-{YYYY}-{uuid-v4}`
pub fn generate_related_rme_id(now: chrono::DateTime<chrono::Utc>) -> String {
    let year = now.format("%Y");
    let uuid = Uuid::new_v4();
    format!("RME-{year}-{uuid}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn generates_rme_id_with_expected_prefix() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 5, 23, 12, 0, 0).unwrap();
        let id = generate_related_rme_id(now);
        assert!(id.starts_with("RME-2026-"));
        assert_eq!(id.len(), "RME-2026-".len() + 36);
    }
}
