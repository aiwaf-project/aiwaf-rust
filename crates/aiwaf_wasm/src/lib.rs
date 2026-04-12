use aiwaf_core::{
    analyze_recent_behavior as core_analyze_recent_behavior,
    extract_features as core_extract_features,
    extract_features_batch_with_state as core_extract_features_batch_with_state,
    finalize_feature_state as core_finalize_feature_state,
    validate_headers as core_validate_headers,
    validate_headers_with_config as core_validate_headers_with_config,
    BehaviorAnalysis, Contamination, FeatureBatchResult, FeatureRecordInput,
    FeatureRecordOutput, FeatureState, IsolationForest as CoreForest,
    IsolationForestState, MaxFeatures, MaxSamples, RecentEntryInput,
};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::JsCast;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use js_sys::Array;
use web_sys::{Headers, Window};

fn headers_js_to_map(headers: JsValue) -> Result<HashMap<String, String>, JsValue> {
    if let Ok(map) = from_value::<HashMap<String, String>>(headers.clone()) {
        return Ok(map);
    }

    // Try treating as a Headers object (e.g., fetch Request headers)
    if let Ok(h) = headers.clone().dyn_into::<Headers>() {
        let mut map = HashMap::new();
        let iter = h.entries();
        loop {
            let next = iter.next()?;
            if next.done() {
                break;
            }
            let pair = Array::from(&next.value());
            if pair.length() >= 2 {
                let key = pair.get(0).as_string().unwrap_or_default();
                let value = pair.get(1).as_string().unwrap_or_default();
                if !key.is_empty() {
                    map.insert(key, value);
                }
            }
        }
        return Ok(map);
    }

    // Try treating as a plain object with string values
    let obj = js_sys::Object::from(headers);
    let keys = js_sys::Object::keys(&obj);
    let mut map = HashMap::new();
    for key in keys.iter() {
        let k = key.as_string().unwrap_or_default();
        if k.is_empty() {
            continue;
        }
        let v = js_sys::Reflect::get(&obj, &key).unwrap_or(JsValue::UNDEFINED);
        let value = v.as_string().unwrap_or_else(|| format!("{v:?}"));
        map.insert(k, value);
    }
    Ok(map)
}

fn add_navigator_ua_if_missing(map: &mut HashMap<String, String>) {
    if map.contains_key("user-agent") {
        return;
    }
    let ua = web_sys::window()
        .and_then(|w: Window| w.navigator().user_agent().ok())
        .unwrap_or_default();
    if !ua.is_empty() {
        map.insert("user-agent".to_string(), ua);
    }
}

#[wasm_bindgen]
pub fn validate_headers(headers: JsValue) -> Result<JsValue, JsValue> {
    let mut map = headers_js_to_map(headers)?;
    add_navigator_ua_if_missing(&mut map);
    to_value(&core_validate_headers(&map)).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn validate_headers_with_config(
    headers: JsValue,
    required_headers: JsValue,
    min_score: JsValue,
) -> Result<JsValue, JsValue> {
    let mut map = headers_js_to_map(headers)?;
    add_navigator_ua_if_missing(&mut map);
    let required: Option<Vec<String>> = if required_headers.is_null() || required_headers.is_undefined() {
        None
    } else {
        Some(from_value(required_headers)?)
    };
    let min_score: Option<i32> = if min_score.is_null() || min_score.is_undefined() {
        None
    } else {
        Some(from_value(min_score)?)
    };
    to_value(&core_validate_headers_with_config(&map, required, min_score)).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn extract_features(records: JsValue, static_keywords: JsValue) -> Result<JsValue, JsValue> {
    let records: Vec<FeatureRecordInput> = from_value(records)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    let out: Vec<FeatureRecordOutput> = core_extract_features(records, keywords);
    to_value(&out).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn extract_features_batch_with_state(
    records: JsValue,
    static_keywords: JsValue,
    state: JsValue,
) -> Result<JsValue, JsValue> {
    let records: Vec<FeatureRecordInput> = from_value(records)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    let state: Option<FeatureState> = if state.is_null() || state.is_undefined() {
        None
    } else {
        Some(from_value(state)?)
    };
    let result: FeatureBatchResult = core_extract_features_batch_with_state(records, keywords, state);
    to_value(&result).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn finalize_feature_state() -> Result<JsValue, JsValue> {
    let result: FeatureBatchResult = core_finalize_feature_state();
    to_value(&result).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn analyze_recent_behavior(entries: JsValue, static_keywords: JsValue) -> Result<JsValue, JsValue> {
    let entries: Vec<RecentEntryInput> = from_value(entries)?;
    let keywords: Vec<String> = from_value(static_keywords)?;
    let result: Option<BehaviorAnalysis> = core_analyze_recent_behavior(entries, keywords);
    to_value(&result).map_err(|e| e.into())
}

struct JsForestConfig {
    n_estimators: usize,
    max_samples: Option<JsValue>,
    contamination: Option<JsValue>,
    max_features: Option<JsValue>,
    bootstrap: bool,
    random_state: Option<u64>,
    verbose: usize,
    warm_start: bool,
}

impl JsForestConfig {
    fn default() -> Self {
        Self {
            n_estimators: 100,
            max_samples: None,
            contamination: None,
            max_features: None,
            bootstrap: false,
            random_state: None,
            verbose: 0,
            warm_start: false,
        }
    }
}

#[wasm_bindgen]
pub struct IsolationForest {
    inner: CoreForest,
}

#[wasm_bindgen]
impl IsolationForest {
    #[wasm_bindgen(constructor)]
    pub fn new(config: Option<JsValue>) -> Result<IsolationForest, JsValue> {
        let cfg = match config {
            None => JsForestConfig::default(),
            Some(v) if v.is_null() || v.is_undefined() => JsForestConfig::default(),
            Some(v) => parse_config_object(v)?,
        };

        let max_samples = parse_max_samples(cfg.max_samples)?;
        let contamination = parse_contamination(cfg.contamination)?;
        let max_features = parse_max_features(cfg.max_features)?;

        let inner = CoreForest::new(
            cfg.n_estimators,
            max_samples,
            contamination,
            max_features,
            cfg.bootstrap,
            cfg.random_state,
            cfg.verbose,
            cfg.warm_start,
        );
        Ok(IsolationForest { inner })
    }

    pub fn fit(&mut self, data: JsValue) -> Result<(), JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        self.inner.fit(data);
        Ok(())
    }

    pub fn retrain(&mut self, data: JsValue) -> Result<(), JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        self.inner.retrain(data);
        Ok(())
    }

    pub fn anomaly_score(&self, point: JsValue) -> Result<f64, JsValue> {
        let point: Vec<f64> = from_value(point)?;
        Ok(self.inner.anomaly_score(&point))
    }

    pub fn is_anomaly(&self, point: JsValue, thresh: Option<f64>) -> Result<bool, JsValue> {
        let point: Vec<f64> = from_value(point)?;
        let t = thresh.unwrap_or(0.5);
        Ok(self.inner.is_anomaly(&point, t))
    }

    pub fn score_samples(&self, data: JsValue) -> Result<JsValue, JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        to_value(&self.inner.score_samples(&data)).map_err(|e| e.into())
    }

    pub fn decision_function(&self, data: JsValue) -> Result<JsValue, JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        to_value(&self.inner.decision_function(&data)).map_err(|e| e.into())
    }

    pub fn predict(&self, data: JsValue) -> Result<JsValue, JsValue> {
        let data: Vec<Vec<f64>> = from_value(data)?;
        to_value(&self.inner.predict(&data)).map_err(|e| e.into())
    }

    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let state: IsolationForestState = self.inner.to_state();
        to_value(&state).map_err(|e| e.into())
    }

    #[allow(unused_variables)]
    #[wasm_bindgen(static_method_of = IsolationForest)]
    pub fn from_json(state: JsValue) -> Result<IsolationForest, JsValue> {
        let state: IsolationForestState = from_value(state)?;
        Ok(IsolationForest {
            inner: CoreForest::from_state(state),
        })
    }
}

fn parse_max_samples(value: Option<JsValue>) -> Result<MaxSamples, JsValue> {
    match value {
        None => Ok(MaxSamples::Auto),
        Some(v) if v.is_null() || v.is_undefined() => Ok(MaxSamples::Auto),
        Some(v) => {
            if let Ok(s) = from_value::<String>(v.clone()) {
                if s == "auto" {
                    return Ok(MaxSamples::Auto);
                }
            }
            if let Ok(i) = from_value::<u32>(v.clone()) {
                return Ok(MaxSamples::Int(i as usize));
            }
            if let Ok(f) = from_value::<f64>(v) {
                return Ok(MaxSamples::Float(f));
            }
            Err(JsValue::from_str("max_samples must be 'auto', int, or float"))
        }
    }
}

fn parse_max_features(value: Option<JsValue>) -> Result<MaxFeatures, JsValue> {
    match value {
        None => Ok(MaxFeatures::Float(1.0)),
        Some(v) if v.is_null() || v.is_undefined() => Ok(MaxFeatures::Float(1.0)),
        Some(v) => {
            if let Ok(i) = from_value::<u32>(v.clone()) {
                return Ok(MaxFeatures::Int(i as usize));
            }
            if let Ok(f) = from_value::<f64>(v) {
                return Ok(MaxFeatures::Float(f));
            }
            Err(JsValue::from_str("max_features must be int or float"))
        }
    }
}

fn parse_contamination(value: Option<JsValue>) -> Result<Contamination, JsValue> {
    match value {
        None => Ok(Contamination::Auto),
        Some(v) if v.is_null() || v.is_undefined() => Ok(Contamination::Auto),
        Some(v) => {
            if let Ok(s) = from_value::<String>(v.clone()) {
                if s == "auto" {
                    return Ok(Contamination::Auto);
                }
            }
            if let Ok(f) = from_value::<f64>(v) {
                if f > 0.0 && f <= 0.5 {
                    return Ok(Contamination::Fixed(f));
                }
            }
            Err(JsValue::from_str("contamination must be 'auto' or float in (0, 0.5]"))
        }
    }
}

fn parse_config_object(value: JsValue) -> Result<JsForestConfig, JsValue> {
    let obj = value.dyn_into::<js_sys::Object>().map_err(|_| {
        JsValue::from_str("config must be an object")
    })?;
    let n_estimators = get_u64(&obj, "n_estimators")?.unwrap_or(100) as usize;
    let bootstrap = get_bool(&obj, "bootstrap")?.unwrap_or(false);
    let verbose = get_u64(&obj, "verbose")?.unwrap_or(0) as usize;
    let warm_start = get_bool(&obj, "warm_start")?.unwrap_or(false);
    let random_state = get_u64(&obj, "random_state")?;
    let max_samples = get_value(&obj, "max_samples");
    let contamination = get_value(&obj, "contamination");
    let max_features = get_value(&obj, "max_features");

    Ok(JsForestConfig {
        n_estimators,
        max_samples,
        contamination,
        max_features,
        bootstrap,
        random_state,
        verbose,
        warm_start,
    })
}

fn get_value(obj: &js_sys::Object, key: &str) -> Option<JsValue> {
    let v = js_sys::Reflect::get(obj, &JsValue::from_str(key)).ok()?;
    if v.is_undefined() || v.is_null() {
        None
    } else {
        Some(v)
    }
}

fn get_u64(obj: &js_sys::Object, key: &str) -> Result<Option<u64>, JsValue> {
    match get_value(obj, key) {
        None => Ok(None),
        Some(v) => {
            let n = js_sys::Number::from(v).value_of();
            if n.is_finite() && n >= 0.0 {
                Ok(Some(n as u64))
            } else {
                Err(JsValue::from_str(&format!("{} must be a non-negative number", key)))
            }
        }
    }
}

fn get_bool(obj: &js_sys::Object, key: &str) -> Result<Option<bool>, JsValue> {
    match get_value(obj, key) {
        None => Ok(None),
        Some(v) => Ok(Some(v.as_bool().unwrap_or(false))),
    }
}
