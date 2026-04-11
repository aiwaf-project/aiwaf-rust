use aiwaf_wasm::{
    analyze_recent_behavior, extract_features, extract_features_batch_with_state,
    finalize_feature_state, validate_headers, IsolationForest,
};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;


#[wasm_bindgen_test]
fn test_validate_headers() {
    let headers = serde_wasm_bindgen::to_value(&serde_json::json!({
        "HTTP_USER_AGENT": "Mozilla/5.0",
        "HTTP_ACCEPT": "text/html",
        "HTTP_ACCEPT_LANGUAGE": "en-US",
        "HTTP_ACCEPT_ENCODING": "gzip, deflate",
        "HTTP_CONNECTION": "keep-alive"
    }))
    .unwrap();
    let reason = validate_headers(headers).unwrap();
    let opt: Option<String> = from_value(reason).unwrap();
    assert!(opt.is_none());
}

#[wasm_bindgen_test]
fn test_extract_features_and_state() {
    let records = to_value(&vec![aiwaf_core::FeatureRecordInput {
        ip: "1.2.3.4".to_string(),
        path_lower: "/wp-admin".to_string(),
        path_len: 9,
        timestamp: 10.0,
        response_time: 0.03,
        status_idx: 3,
        kw_check: true,
        total_404: 5,
    }])
    .unwrap();
    let keywords = serde_wasm_bindgen::to_value(&vec!["wp"]).unwrap();
    let out = extract_features(records, keywords).unwrap();
    assert!(out.is_object());

    let records = to_value(&vec![aiwaf_core::FeatureRecordInput {
        ip: "1.2.3.4".to_string(),
        path_lower: "/wp-admin".to_string(),
        path_len: 9,
        timestamp: 10.0,
        response_time: 0.03,
        status_idx: 3,
        kw_check: true,
        total_404: 5,
    }])
    .unwrap();
    let keywords = serde_wasm_bindgen::to_value(&vec!["wp"]).unwrap();
    let batch = extract_features_batch_with_state(records, keywords, JsValue::NULL).unwrap();
    assert!(batch.is_object());
    let _state = finalize_feature_state().unwrap();
}

#[wasm_bindgen_test]
fn test_analyze_recent_behavior() {
    let entries = to_value(&vec![
        aiwaf_core::RecentEntryInput {
            path_lower: "/wp-admin".to_string(),
            timestamp: 1.0,
            status: 404,
            kw_check: true,
        },
        aiwaf_core::RecentEntryInput {
            path_lower: "/.env".to_string(),
            timestamp: 2.0,
            status: 404,
            kw_check: true,
        },
    ])
    .unwrap();
    let keywords = serde_wasm_bindgen::to_value(&vec!["wp"]).unwrap();
    let res = analyze_recent_behavior(entries, keywords).unwrap();
    assert!(res.is_object() || res.is_null());
}

#[wasm_bindgen_test]
fn test_isolation_forest_roundtrip() {
    let config = serde_wasm_bindgen::to_value(&serde_json::json!({
        "n_estimators": 10,
        "max_samples": 8,
        "contamination": "auto",
        "max_features": 1.0,
        "bootstrap": false,
        "random_state": 7,
        "warm_start": false
    }))
    .unwrap();
    let mut forest = IsolationForest::new(Some(config)).unwrap();
    let data = to_value(&vec![vec![0.0], vec![1.0], vec![2.0], vec![10.0]]).unwrap();
    forest.fit(data).unwrap();
    let score = forest
        .anomaly_score(to_value(&vec![10.0]).unwrap())
        .unwrap();
    assert!(score >= 0.0);
    let state = forest.to_json().unwrap();
    let mut forest2 = IsolationForest::from_json(state).unwrap();
    forest2
        .retrain(to_value(&vec![vec![0.1], vec![0.2], vec![9.5]]).unwrap())
        .unwrap();
}
