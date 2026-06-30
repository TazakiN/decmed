/// Format an encounter/RME id. This is not a segment metadata index.
///
/// The sequence must come from a centralized atomic counter owned by the PRE
/// server; callers must not derive it from on-chain metadata.index.
pub fn format_related_rme_id(sequence: u64) -> String {
    format!("RME-{sequence:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_incremental_rme_id() {
        assert_eq!(format_related_rme_id(1), "RME-000001");
        assert_eq!(format_related_rme_id(123), "RME-000123");
    }
}
