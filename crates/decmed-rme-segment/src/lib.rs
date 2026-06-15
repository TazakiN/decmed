mod administrative_payload;
mod category;
mod crypto;
mod error;
mod types;
mod validation;

// Re-export everything at the crate root to preserve the original public API.
pub use administrative_payload::{
    administrative_general_payload_from_fields, administrative_general_payload_from_value,
    AdministrativeGeneralPayload,
};
pub use category::{
    DatasetCategory, FunctionCategory, ALL_DATASET_CATEGORIES, ALL_FUNCTION_CATEGORIES,
};
pub use crypto::{canonical_json, ciphertext_integrity_hash_from_base64, payload_hash, sha256_hex};
pub use error::SegmentValidationError;
pub use types::{
    ClientEncryptedRmeSegment, CreateRmeSegmentRequest, CreateRmeSegmentResponse, RmeSegmentData,
    RmeSegmentMetadata,
};
pub use validation::{
    assert_no_plaintext_medical_fields, assert_segment_pair_consistent,
    assert_valid_segment_category, get_allowed_function_categories, is_valid_segment_category,
};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::json;
    use uuid::Uuid;

    fn sample_request(payload: serde_json::Value) -> CreateRmeSegmentRequest {
        CreateRmeSegmentRequest {
            related_rme_id: "rme-2026-0001".to_string(),
            patient_address: "iota:patient-address".to_string(),
            service_date: "2026-05-18".to_string(),
            author_address: "iota:doctor-address".to_string(),
            dataset_category: DatasetCategory::RAWAT_JALAN,
            function_category: FunctionCategory::ANAMNESIS,
            payload,
        }
    }

    fn sample_metadata(ciphertext: &[u8]) -> RmeSegmentMetadata {
        RmeSegmentMetadata {
            segment_id: "b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31".to_string(),
            related_rme_id: "rme-2026-0001".to_string(),
            patient_address: "iota:patient-address".to_string(),
            hospital_cid: "hospital-001".to_string(),
            dataset_category: DatasetCategory::RAWAT_JALAN,
            function_category: FunctionCategory::ANAMNESIS,
            ipfs_cid: "bafy...".to_string(),
            integrity_hash: sha256_hex(ciphertext),
            capsule: "pre-capsule-value".to_string(),
            enc_key_and_nonce: "encrypted-key-and-nonce-value".to_string(),
            created_at: "2026-05-18T10:30:00.000Z".to_string(),
            author_address: "iota:doctor-address".to_string(),
            updated_at: None,
        }
    }

    #[test]
    fn dataset_category_contains_required_values() {
        assert_eq!(
            DatasetCategory::all(),
            &[
                DatasetCategory::RAWAT_JALAN,
                DatasetCategory::RAWAT_INAP,
                DatasetCategory::LABORATORIUM,
                DatasetCategory::APOTEK,
            ]
        );

        let serialized = serde_json::to_value(DatasetCategory::RAWAT_JALAN).unwrap();
        assert_eq!(serialized, json!("RAWAT_JALAN"));
    }

    #[test]
    fn function_category_contains_required_values() {
        assert_eq!(FunctionCategory::all().len(), 15);
        assert!(FunctionCategory::all().contains(&FunctionCategory::ADMINISTRATIVE_GENERAL));
        assert!(FunctionCategory::all().contains(&FunctionCategory::DISPENSING));

        let serialized = serde_json::to_value(FunctionCategory::LABORATORIUM).unwrap();
        assert_eq!(serialized, json!("LABORATORIUM"));
    }

    #[test]
    fn valid_combinations_are_accepted() {
        assert!(is_valid_segment_category(
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ANAMNESIS
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::INSTRUKSI_MEDIK_DAN_KEPERAWATAN
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::LABORATORIUM,
            FunctionCategory::LABORATORIUM
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::APOTEK,
            FunctionCategory::PERESEPAN
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ADMINISTRATIVE_GENERAL
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::LABORATORIUM,
            FunctionCategory::ADMINISTRATIVE_GENERAL
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::APOTEK,
            FunctionCategory::ADMINISTRATIVE_GENERAL
        ));
        assert!(is_valid_segment_category(
            DatasetCategory::RAWAT_INAP,
            FunctionCategory::ADMINISTRATIVE_GENERAL
        ));
    }

    #[test]
    fn invalid_combinations_are_rejected() {
        assert!(assert_valid_segment_category(
            DatasetCategory::APOTEK,
            FunctionCategory::ANAMNESIS
        )
        .is_err());
        assert!(assert_valid_segment_category(
            DatasetCategory::LABORATORIUM,
            FunctionCategory::PERESEPAN
        )
        .is_err());
        assert!(assert_valid_segment_category(
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::DISPENSING
        )
        .is_err());
    }

    #[test]
    fn allowed_functions_are_exposed_by_dataset() {
        for dataset in DatasetCategory::all() {
            assert!(
                get_allowed_function_categories(*dataset)
                    .contains(&FunctionCategory::ADMINISTRATIVE_GENERAL),
                "{dataset:?} should include ADMINISTRATIVE_GENERAL"
            );
        }
        let rawat_jalan = get_allowed_function_categories(DatasetCategory::RAWAT_JALAN);
        assert_eq!(rawat_jalan.len(), 11);
        assert!(rawat_jalan.contains(&FunctionCategory::INSTRUKSI_MEDIK_DAN_KEPERAWATAN));
        assert_eq!(
            get_allowed_function_categories(DatasetCategory::LABORATORIUM).len(),
            3
        );
        assert_eq!(
            get_allowed_function_categories(DatasetCategory::APOTEK).len(),
            4
        );
        assert!(get_allowed_function_categories(DatasetCategory::RAWAT_INAP)
            .contains(&FunctionCategory::PERENCANAAN_PEMULANGAN));
    }

    #[test]
    fn on_chain_metadata_does_not_contain_payload() {
        let metadata = sample_metadata(b"encrypted segment");
        metadata.validate().unwrap();

        let value = serde_json::to_value(metadata).unwrap();
        assert!(value.get("payload").is_none());
        assert!(value.get("patient_address").is_some());
        assert!(assert_no_plaintext_medical_fields(&value).is_ok());
    }

    #[test]
    fn off_chain_segment_contains_payload_and_payload_hash() {
        let payload = json!({
            "riwayat_penyakit_sekarang": "Demam",
            "keluhan_utama": "Batuk"
        });
        let segment_id = Uuid::parse_str("b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31").unwrap();
        let segment = RmeSegmentData::new(segment_id, sample_request(payload.clone())).unwrap();

        assert_eq!(segment.payload, payload);
        assert_eq!(segment.payload_hash, payload_hash(&payload));
        let value = serde_json::to_value(&segment).unwrap();
        let removed_encounter_key = ["encounter", "id"].join("_");
        assert!(value.get(&removed_encounter_key).is_none());
        segment.validate().unwrap();
    }

    #[test]
    fn segment_identity_is_consistent_between_off_chain_and_on_chain() {
        let payload = json!({
            "keluhan_utama": "Demam dan batuk sejak 3 hari"
        });
        let segment_id = Uuid::parse_str("b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31").unwrap();
        let off_chain = RmeSegmentData::new(segment_id, sample_request(payload)).unwrap();
        let on_chain = sample_metadata(b"encrypted segment");

        assert_segment_pair_consistent(&off_chain, &on_chain).unwrap();
    }

    #[test]
    fn serializer_outputs_snake_case_json_keys() {
        let metadata = sample_metadata(b"encrypted segment");
        let stored = STANDARD.encode(serde_json::to_vec(&metadata).unwrap());
        let decoded = STANDARD.decode(stored).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let legacy_algorithm_key = ["encryption", "algo"].join("_");

        assert!(value.get("segment_id").is_some());
        assert!(value.get("related_rme_id").is_some());
        assert!(value.get("dataset_category").is_some());
        assert!(value.get("function_category").is_some());
        assert!(value.get("ipfs_cid").is_some());
        assert!(value.get("enc_key_and_nonce").is_some());
        assert!(value.get(&legacy_algorithm_key).is_none());
        assert!(value.get("created_at").is_some());
        assert!(value.get("segmentId").is_none());
        assert!(value.get("datasetCategory").is_none());
    }

    #[test]
    fn integrity_hash_is_calculated_from_encrypted_segment() {
        let ciphertext = b"ciphertext bytes";
        let plaintext = b"plaintext medical data";
        let enc_data = STANDARD.encode(ciphertext);

        assert_eq!(
            ciphertext_integrity_hash_from_base64(&enc_data).unwrap(),
            sha256_hex(ciphertext)
        );
        assert_ne!(sha256_hex(ciphertext), sha256_hex(plaintext));
    }

    #[test]
    fn payload_hash_is_calculated_from_canonical_json_payload() {
        let left = json!({
            "b": 2,
            "a": {
                "d": true,
                "c": "x"
            }
        });
        let right = json!({
            "a": {
                "c": "x",
                "d": true
            },
            "b": 2
        });

        assert_eq!(canonical_json(&left), r#"{"a":{"c":"x","d":true},"b":2}"#);
        assert_eq!(payload_hash(&left), payload_hash(&right));
    }

    #[test]
    fn client_encrypted_segment_validates_integrity_and_builds_metadata() {
        let ciphertext = b"encrypted segment";
        let client_segment = ClientEncryptedRmeSegment {
            segment_id: "b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31".to_string(),
            related_rme_id: "rme-2026-0001".to_string(),
            patient_address: "iota:patient-address".to_string(),
            hospital_cid: "hospital-001".to_string(),
            dataset_category: DatasetCategory::RAWAT_JALAN,
            function_category: FunctionCategory::ANAMNESIS,
            integrity_hash: sha256_hex(ciphertext),
            capsule: "pre-capsule-value".to_string(),
            enc_data: STANDARD.encode(ciphertext),
            enc_key_and_nonce: "encrypted-key-and-nonce-value".to_string(),
            author_address: "iota:doctor-address".to_string(),
        };

        client_segment.validate().unwrap();
        let metadata = client_segment.into_metadata(
            "bafy...".to_string(),
            "2026-05-18T10:30:00.000Z".to_string(),
        );

        assert_eq!(metadata.ipfs_cid, "bafy...");
        let value = serde_json::to_value(metadata).unwrap();
        let legacy_algorithm_key = ["encryption", "algo"].join("_");
        assert_eq!(value.get("hospital_cid"), Some(&json!("hospital-001")));
        assert!(value.get("hospital_id").is_none());
        assert!(value.get("fasyankes_id").is_none());
        assert!(value.get("enc_data").is_none());
        assert!(value.get(&legacy_algorithm_key).is_none());
    }

    #[test]
    fn legacy_algorithm_field_is_ignored() {
        let ciphertext = b"encrypted segment";
        let legacy_algorithm_key = ["encryption", "algo"].join("_");
        let legacy_algorithm_value = ["AES", "256", "GCM"].join("-");
        let mut metadata = serde_json::to_value(sample_metadata(ciphertext)).unwrap();
        metadata.as_object_mut().unwrap().insert(
            legacy_algorithm_key.clone(),
            json!(legacy_algorithm_value.clone()),
        );

        let decoded: RmeSegmentMetadata = serde_json::from_value(metadata).unwrap();
        decoded.validate().unwrap();

        let client_segment = ClientEncryptedRmeSegment {
            segment_id: "b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31".to_string(),
            related_rme_id: "rme-2026-0001".to_string(),
            patient_address: "iota:patient-address".to_string(),
            hospital_cid: "hospital-001".to_string(),
            dataset_category: DatasetCategory::RAWAT_JALAN,
            function_category: FunctionCategory::ANAMNESIS,
            integrity_hash: sha256_hex(ciphertext),
            capsule: "pre-capsule-value".to_string(),
            enc_data: STANDARD.encode(ciphertext),
            enc_key_and_nonce: "encrypted-key-and-nonce-value".to_string(),
            author_address: "iota:doctor-address".to_string(),
        };
        let mut client_value = serde_json::to_value(client_segment).unwrap();
        client_value
            .as_object_mut()
            .unwrap()
            .insert(legacy_algorithm_key, json!(legacy_algorithm_value));

        let decoded: ClientEncryptedRmeSegment = serde_json::from_value(client_value).unwrap();
        decoded.validate().unwrap();
    }

    #[test]
    fn legacy_hospital_identifiers_deserialize_as_hospital_cid() {
        let mut metadata = serde_json::to_value(sample_metadata(b"encrypted segment")).unwrap();
        let hospital_cid = metadata
            .as_object_mut()
            .unwrap()
            .remove("hospital_cid")
            .unwrap();
        metadata
            .as_object_mut()
            .unwrap()
            .insert("hospital_id".to_string(), hospital_cid.clone());

        let decoded: RmeSegmentMetadata = serde_json::from_value(metadata).unwrap();
        assert_eq!(decoded.hospital_cid, "hospital-001");

        let mut legacy_fasyankes =
            serde_json::to_value(sample_metadata(b"encrypted segment")).unwrap();
        legacy_fasyankes
            .as_object_mut()
            .unwrap()
            .remove("hospital_cid");
        legacy_fasyankes
            .as_object_mut()
            .unwrap()
            .insert("fasyankes_id".to_string(), hospital_cid);
        let decoded: RmeSegmentMetadata = serde_json::from_value(legacy_fasyankes).unwrap();
        assert_eq!(decoded.hospital_cid, "hospital-001");
    }

    #[test]
    fn legacy_hospital_identifiers_are_rejected_for_new_write_payloads() {
        let client_segment = ClientEncryptedRmeSegment {
            segment_id: "b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31".to_string(),
            related_rme_id: "rme-2026-0001".to_string(),
            patient_address: "iota:patient-address".to_string(),
            hospital_cid: "hospital-001".to_string(),
            dataset_category: DatasetCategory::RAWAT_JALAN,
            function_category: FunctionCategory::ANAMNESIS,
            integrity_hash: sha256_hex(b"encrypted segment"),
            capsule: "pre-capsule-value".to_string(),
            enc_data: STANDARD.encode(b"encrypted segment"),
            enc_key_and_nonce: "encrypted-key-and-nonce-value".to_string(),
            author_address: "iota:doctor-address".to_string(),
        };
        let mut value = serde_json::to_value(client_segment).unwrap();
        let hospital_cid = value
            .as_object_mut()
            .unwrap()
            .remove("hospital_cid")
            .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("hospital_id".to_string(), hospital_cid.clone());

        assert!(serde_json::from_value::<ClientEncryptedRmeSegment>(value).is_err());

        let mut value =
            serde_json::to_value(ClientEncryptedRmeSegment {
                segment_id: "b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31".to_string(),
                related_rme_id: "rme-2026-0001".to_string(),
                patient_address: "iota:patient-address".to_string(),
                hospital_cid: "hospital-001".to_string(),
                dataset_category: DatasetCategory::RAWAT_JALAN,
                function_category: FunctionCategory::ANAMNESIS,
                integrity_hash: sha256_hex(b"encrypted segment"),
                capsule: "pre-capsule-value".to_string(),
                enc_data: STANDARD.encode(b"encrypted segment"),
                enc_key_and_nonce: "encrypted-key-and-nonce-value".to_string(),
                author_address: "iota:doctor-address".to_string(),
            })
            .unwrap();
        value.as_object_mut().unwrap().remove("hospital_cid");
        value
            .as_object_mut()
            .unwrap()
            .insert("fasyankes_id".to_string(), hospital_cid);
        assert!(serde_json::from_value::<ClientEncryptedRmeSegment>(value).is_err());
    }
}
