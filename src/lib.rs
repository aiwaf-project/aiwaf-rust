#![allow(unsafe_op_in_unsafe_fn)]
use aiwaf_core::{
    analyze_recent_behavior as core_analyze_recent_behavior,
    extract_features as core_extract_features,
    extract_features_batch_with_state as core_extract_features_batch_with_state,
    finalize_feature_state as core_finalize_feature_state,
    validate_headers as core_validate_headers,
    validate_headers_with_config as core_validate_headers_with_config,
    BehaviorAnalysis, Contamination, FeatureBatchResult, FeatureRecordInput,
    FeatureRecordOutput, FeatureState, IsolationForest as CoreForest,
    IsolationForestState, IsolationTreeState, MaxFeatures, MaxSamples,
    RecentEntryInput,
};
use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::HashMap;

fn headers_to_map(headers: &Bound<'_, PyDict>) -> PyResult<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (k, v) in headers.iter() {
        let key: String = k.extract()?;
        let value = v.str()?.to_string_lossy().into_owned();
        map.insert(key, value);
    }
    Ok(map)
}

fn map_to_pydict<'py>(py: Python<'py>, map: &HashMap<String, Vec<f64>>) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new_bound(py);
    for (k, vals) in map.iter() {
        let list = PyList::new_bound(py, vals.iter().copied());
        dict.set_item(k, list)?;
    }
    Ok(dict.into())
}

fn pydict_to_map(state: &Bound<'_, PyDict>) -> PyResult<HashMap<String, Vec<f64>>> {
    let mut map = HashMap::new();
    for (k, v) in state.iter() {
        let key: String = k.extract()?;
        let list = v.downcast::<PyList>()?;
        let mut vals = Vec::with_capacity(list.len());
        for item in list.iter() {
            vals.push(item.extract::<f64>()?);
        }
        map.insert(key, vals);
    }
    Ok(map)
}

#[derive(Clone)]
struct PyFeatureRecordInput(FeatureRecordInput);

impl<'py> FromPyObject<'py> for PyFeatureRecordInput {
    fn extract(ob: &'py PyAny) -> PyResult<Self> {
        let dict: &PyDict = ob.downcast()?;
        let get_required = |key: &str| -> PyResult<&PyAny> {
            dict.get_item(key)?
                .ok_or_else(|| PyErr::new::<PyKeyError, _>(key.to_string()))
        };
        Ok(Self(FeatureRecordInput {
            ip: get_required("ip")?.extract()?,
            path_lower: get_required("path_lower")?.extract()?,
            path_len: get_required("path_len")?.extract()?,
            timestamp: get_required("timestamp")?.extract()?,
            response_time: get_required("response_time")?.extract()?,
            status_idx: get_required("status_idx")?.extract()?,
            kw_check: get_required("kw_check")?.extract()?,
            total_404: get_required("total_404")?.extract()?,
        }))
    }
}

#[derive(Clone)]
struct PyRecentEntryInput(RecentEntryInput);

impl<'py> FromPyObject<'py> for PyRecentEntryInput {
    fn extract(ob: &'py PyAny) -> PyResult<Self> {
        let dict: &PyDict = ob.downcast()?;
        let get_required = |key: &str| -> PyResult<&PyAny> {
            dict.get_item(key)?
                .ok_or_else(|| PyErr::new::<PyKeyError, _>(key.to_string()))
        };
        Ok(Self(RecentEntryInput {
            path_lower: get_required("path_lower")?.extract()?,
            timestamp: get_required("timestamp")?.extract()?,
            status: get_required("status")?.extract()?,
            kw_check: get_required("kw_check")?.extract()?,
        }))
    }
}

#[pyfunction]
fn validate_headers(headers: Bound<'_, PyDict>) -> PyResult<Option<String>> {
    let map = headers_to_map(&headers)?;
    Ok(core_validate_headers(&map))
}

#[pyfunction]
fn validate_headers_with_config(
    headers: Bound<'_, PyDict>,
    required_headers: Option<Vec<String>>,
    min_score: Option<i32>,
) -> PyResult<Option<String>> {
    let map = headers_to_map(&headers)?;
    Ok(core_validate_headers_with_config(&map, required_headers, min_score))
}

#[pyfunction]
fn extract_features<'py>(
    py: Python<'py>,
    records: Vec<PyFeatureRecordInput>,
    static_keywords: Vec<String>,
) -> PyResult<Vec<Py<PyDict>>> {
    let core_records: Vec<FeatureRecordInput> = records.into_iter().map(|r| r.0).collect();
    let output: Vec<FeatureRecordOutput> = core_extract_features(core_records, static_keywords);
    output
        .into_iter()
        .map(|rec| feature_output_to_pydict(py, &rec))
        .collect()
}

#[pyfunction]
fn extract_features_batch_with_state<'py>(
    py: Python<'py>,
    records: Vec<PyFeatureRecordInput>,
    static_keywords: Vec<String>,
    state: Option<Bound<'py, PyAny>>,
) -> PyResult<Py<PyDict>> {
    let state_map = if let Some(state_any) = state {
        let dict = state_any.downcast::<PyDict>()?;
        match dict.get_item("timestamps_by_ip")? {
            Some(v) => {
                let ts_dict = v.downcast::<PyDict>()?;
                Some(FeatureState {
                    timestamps_by_ip: pydict_to_map(&ts_dict)?,
                })
            }
            None => None,
        }
    } else {
        None
    };

    let core_records: Vec<FeatureRecordInput> = records.into_iter().map(|r| r.0).collect();
    let result: FeatureBatchResult =
        core_extract_features_batch_with_state(core_records, static_keywords, state_map);

    let features: Vec<Py<PyDict>> = result
        .features
        .iter()
        .map(|rec| feature_output_to_pydict(py, rec))
        .collect::<PyResult<Vec<_>>>()?;

    let result_dict = PyDict::new_bound(py);
    result_dict.set_item("features", features)?;
    let state_dict = PyDict::new_bound(py);
    state_dict.set_item(
        "timestamps_by_ip",
        map_to_pydict(py, &result.state.timestamps_by_ip)?,
    )?;
    result_dict.set_item("state", state_dict)?;
    Ok(result_dict.into())
}

#[pyfunction]
fn finalize_feature_state<'py>(
    py: Python<'py>,
    _static_keywords: Vec<String>,
    _state: Option<Bound<'py, PyAny>>,
) -> PyResult<Py<PyDict>> {
    let _ = core_finalize_feature_state();
    let result = PyDict::new_bound(py);
    let empty: Vec<Py<PyDict>> = Vec::new();
    result.set_item("features", empty)?;
    Ok(result.into())
}

#[pyfunction]
fn analyze_recent_behavior<'py>(
    py: Python<'py>,
    entries: Vec<PyRecentEntryInput>,
    static_keywords: Vec<String>,
) -> PyResult<Option<Py<PyDict>>> {
    let core_entries: Vec<RecentEntryInput> = entries.into_iter().map(|e| e.0).collect();
    let result: Option<BehaviorAnalysis> =
        core_analyze_recent_behavior(core_entries, static_keywords);
    match result {
        None => Ok(None),
        Some(r) => {
            let dict = PyDict::new_bound(py);
            dict.set_item("avg_kw_hits", r.avg_kw_hits)?;
            dict.set_item("max_404s", r.max_404s)?;
            dict.set_item("avg_burst", r.avg_burst)?;
            dict.set_item("total_requests", r.total_requests)?;
            dict.set_item("scanning_404s", r.scanning_404s)?;
            dict.set_item("legitimate_404s", r.legitimate_404s)?;
            dict.set_item("should_block", r.should_block)?;
            Ok(Some(dict.into()))
        }
    }
}

#[pyclass]
struct IsolationForest {
    inner: CoreForest,
}

#[pymethods]
impl IsolationForest {
    #[new]
    #[pyo3(
        signature = (
            *,
            n_estimators = 100,
            max_samples = None,
            contamination = None,
            max_features = None,
            bootstrap = false,
            n_jobs = None,
            random_state = None,
            verbose = 0,
            warm_start = false
        )
    )]
    fn new(
        n_estimators: usize,
        max_samples: Option<Bound<'_, PyAny>>,
        contamination: Option<Bound<'_, PyAny>>,
        max_features: Option<Bound<'_, PyAny>>,
        bootstrap: bool,
        n_jobs: Option<i32>,
        random_state: Option<u64>,
        verbose: usize,
        warm_start: bool,
    ) -> PyResult<Self> {
        let _ = n_jobs;
        let max_samples = parse_max_samples(max_samples)?;
        let contamination = parse_contamination(contamination)?;
        let max_features = parse_max_features(max_features)?;

        Ok(Self {
            inner: CoreForest::new(
                n_estimators,
                max_samples,
                contamination,
                max_features,
                bootstrap,
                random_state,
                verbose,
                warm_start,
            ),
        })
    }

    fn fit(&mut self, data: Vec<Vec<f64>>) {
        self.inner.fit(data);
    }

    fn retrain(&mut self, data: Vec<Vec<f64>>) {
        self.inner.retrain(data);
    }

    fn anomaly_score(&self, point: Vec<f64>) -> f64 {
        self.inner.anomaly_score(&point)
    }

    #[pyo3(signature = (point, thresh = 0.5))]
    fn is_anomaly(&self, point: Vec<f64>, thresh: f64) -> bool {
        self.inner.is_anomaly(&point, thresh)
    }

    fn score_samples(&self, data: Vec<Vec<f64>>) -> Vec<f64> {
        self.inner.score_samples(&data)
    }

    fn decision_function(&self, data: Vec<Vec<f64>>) -> Vec<f64> {
        self.inner.decision_function(&data)
    }

    fn predict(&self, data: Vec<Vec<f64>>) -> Vec<i32> {
        self.inner.predict(&data)
    }

    fn to_json<'py>(&self, py: Python<'py>) -> PyResult<Py<PyDict>> {
        let state = self.inner.to_state();
        state_to_pydict(py, &state)
    }

    #[staticmethod]
    fn from_json(obj: Bound<'_, PyAny>) -> PyResult<Self> {
        let dict = obj.downcast::<PyDict>()?;
        let state = pydict_to_state(dict)?;
        Ok(Self {
            inner: CoreForest::from_state(state),
        })
    }
}

fn parse_max_samples(value: Option<Bound<'_, PyAny>>) -> PyResult<MaxSamples> {
    match value {
        None => Ok(MaxSamples::Auto),
        Some(v) if v.is_none() => Ok(MaxSamples::Auto),
        Some(v) => {
            if let Ok(s) = v.extract::<String>() {
                if s == "auto" {
                    return Ok(MaxSamples::Auto);
                }
            }
            if let Ok(i) = v.extract::<usize>() {
                return Ok(MaxSamples::Int(i));
            }
            if let Ok(f) = v.extract::<f64>() {
                return Ok(MaxSamples::Float(f));
            }
            Err(PyErr::new::<PyValueError, _>(
                "max_samples must be 'auto', int, or float",
            ))
        }
    }
}

fn parse_max_features(value: Option<Bound<'_, PyAny>>) -> PyResult<MaxFeatures> {
    match value {
        None => Ok(MaxFeatures::Float(1.0)),
        Some(v) if v.is_none() => Ok(MaxFeatures::Float(1.0)),
        Some(v) => {
            if let Ok(i) = v.extract::<usize>() {
                return Ok(MaxFeatures::Int(i));
            }
            if let Ok(f) = v.extract::<f64>() {
                return Ok(MaxFeatures::Float(f));
            }
            Err(PyErr::new::<PyValueError, _>(
                "max_features must be int or float",
            ))
        }
    }
}

fn parse_contamination(value: Option<Bound<'_, PyAny>>) -> PyResult<Contamination> {
    match value {
        None => Ok(Contamination::Auto),
        Some(v) if v.is_none() => Ok(Contamination::Auto),
        Some(v) => {
            if let Ok(s) = v.extract::<String>() {
                if s == "auto" {
                    return Ok(Contamination::Auto);
                }
            }
            if let Ok(f) = v.extract::<f64>() {
                if f > 0.0 && f <= 0.5 {
                    return Ok(Contamination::Fixed(f));
                }
            }
            Err(PyErr::new::<PyValueError, _>(
                "contamination must be 'auto' or float in (0, 0.5]",
            ))
        }
    }
}

fn tree_state_to_pydict<'py>(
    py: Python<'py>,
    state: &IsolationTreeState,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new_bound(py);
    dict.set_item("depth", state.depth)?;
    dict.set_item("maxDepth", state.max_depth)?;
    dict.set_item("splitAttr", state.split_attr)?;
    dict.set_item("splitValue", state.split_value)?;
    dict.set_item("size", state.size)?;
    if let Some(left) = &state.left {
        dict.set_item("left", tree_state_to_pydict(py, left)?)?;
    } else {
        dict.set_item("left", py.None())?;
    }
    if let Some(right) = &state.right {
        dict.set_item("right", tree_state_to_pydict(py, right)?)?;
    } else {
        dict.set_item("right", py.None())?;
    }
    Ok(dict.into())
}

fn feature_output_to_pydict<'py>(
    py: Python<'py>,
    rec: &FeatureRecordOutput,
) -> PyResult<Py<PyDict>> {
    let feature = PyDict::new_bound(py);
    feature.set_item("ip", rec.ip.clone())?;
    feature.set_item("path_len", rec.path_len)?;
    feature.set_item("kw_hits", rec.kw_hits)?;
    feature.set_item("resp_time", rec.resp_time)?;
    feature.set_item("status_idx", rec.status_idx)?;
    feature.set_item("burst_count", rec.burst_count)?;
    feature.set_item("total_404", rec.total_404)?;
    Ok(feature.into())
}

fn state_to_pydict<'py>(py: Python<'py>, state: &IsolationForestState) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new_bound(py);
    dict.set_item("nEstimators", state.n_estimators)?;
    dict.set_item("maxSamples", max_samples_to_py(py, &state.max_samples))?;
    dict.set_item("contamination", contamination_to_py(py, &state.contamination))?;
    dict.set_item("maxFeatures", max_features_to_py(py, &state.max_features))?;
    dict.set_item("bootstrap", state.bootstrap)?;
    dict.set_item("randomState", state.random_state)?;
    dict.set_item("verbose", state.verbose)?;
    dict.set_item("warmStart", state.warm_start)?;
    dict.set_item("maxSamples_", state.max_samples_)?;
    dict.set_item("maxFeatures_", state.max_features_)?;
    dict.set_item("offset_", state.offset_)?;
    dict.set_item("nFeaturesIn_", state.n_features_in_)?;
    let trees: Vec<Py<PyDict>> = state
        .trees
        .iter()
        .map(|t| tree_state_to_pydict(py, t))
        .collect::<PyResult<Vec<_>>>()?;
    dict.set_item("trees", trees)?;
    let feats = PyList::new_bound(py, state.estimators_features.iter().map(|v| {
        PyList::new_bound(py, v.iter().copied())
    }));
    dict.set_item("estimatorsFeatures", feats)?;
    Ok(dict.into())
}

fn pydict_to_tree_state(dict: &Bound<'_, PyDict>) -> PyResult<IsolationTreeState> {
    let depth: usize = dict.get_item("depth")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("depth".to_string())
    })?.extract()?;
    let max_depth: usize = dict.get_item("maxDepth")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("maxDepth".to_string())
    })?.extract()?;
    let split_attr: Option<usize> = dict.get_item("splitAttr")?.unwrap().extract()?;
    let split_value: Option<f64> = dict.get_item("splitValue")?.unwrap().extract()?;
    let size: usize = dict.get_item("size")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("size".to_string())
    })?.extract()?;
    let left = match dict.get_item("left")? {
        Some(v) if !v.is_none() => {
            let ld = v.downcast::<PyDict>()?;
            Some(Box::new(pydict_to_tree_state(&ld)?))
        }
        _ => None,
    };
    let right = match dict.get_item("right")? {
        Some(v) if !v.is_none() => {
            let rd = v.downcast::<PyDict>()?;
            Some(Box::new(pydict_to_tree_state(&rd)?))
        }
        _ => None,
    };
    Ok(IsolationTreeState {
        depth,
        max_depth,
        split_attr,
        split_value,
        size,
        left,
        right,
    })
}

fn pydict_to_state(dict: &Bound<'_, PyDict>) -> PyResult<IsolationForestState> {
    let n_estimators: usize = dict.get_item("nEstimators")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("nEstimators".to_string())
    })?.extract()?;
    let max_samples = parse_max_samples(dict.get_item("maxSamples")?)?;
    let contamination = parse_contamination(dict.get_item("contamination")?)?;
    let max_features = parse_max_features(dict.get_item("maxFeatures")?)?;
    let bootstrap: bool = dict.get_item("bootstrap")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("bootstrap".to_string())
    })?.extract()?;
    let random_state: Option<u64> = dict
        .get_item("randomState")?
        .map(|v| v.extract())
        .transpose()?
        .flatten();
    let verbose: usize = dict.get_item("verbose")?.unwrap().extract()?;
    let warm_start: bool = dict.get_item("warmStart")?.unwrap().extract()?;
    let max_samples_: usize = dict.get_item("maxSamples_")?.unwrap().extract()?;
    let max_features_: usize = dict.get_item("maxFeatures_")?.unwrap().extract()?;
    let offset_: f64 = dict.get_item("offset_")?.unwrap().extract()?;
    let n_features_in_: usize = dict.get_item("nFeaturesIn_")?.unwrap().extract()?;
    let trees_any = dict.get_item("trees")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("trees".to_string())
    })?;
    let trees_list = trees_any.downcast::<PyList>()?;
    let mut trees = Vec::with_capacity(trees_list.len());
    for item in trees_list.iter() {
        let tree_dict = item.downcast::<PyDict>()?;
        trees.push(pydict_to_tree_state(&tree_dict)?);
    }
    let feats_any = dict.get_item("estimatorsFeatures")?.ok_or_else(|| {
        PyErr::new::<PyKeyError, _>("estimatorsFeatures".to_string())
    })?;
    let feats_list = feats_any.downcast::<PyList>()?;
    let mut estimators_features = Vec::with_capacity(feats_list.len());
    for item in feats_list.iter() {
        let list = item.downcast::<PyList>()?;
        let mut v = Vec::with_capacity(list.len());
        for idx in list.iter() {
            v.push(idx.extract::<usize>()?);
        }
        estimators_features.push(v);
    }

    Ok(IsolationForestState {
        n_estimators,
        max_samples,
        contamination,
        max_features,
        bootstrap,
        random_state,
        verbose,
        warm_start,
        max_samples_,
        max_features_,
        offset_,
        n_features_in_,
        trees,
        estimators_features,
    })
}

fn max_samples_to_py<'py>(py: Python<'py>, value: &MaxSamples) -> PyObject {
    match value {
        MaxSamples::Auto => "auto".into_py(py),
        MaxSamples::Int(v) => (*v as u64).into_py(py),
        MaxSamples::Float(v) => (*v).into_py(py),
    }
}

fn max_features_to_py<'py>(py: Python<'py>, value: &MaxFeatures) -> PyObject {
    match value {
        MaxFeatures::Int(v) => (*v as u64).into_py(py),
        MaxFeatures::Float(v) => (*v).into_py(py),
    }
}

fn contamination_to_py<'py>(py: Python<'py>, value: &Contamination) -> PyObject {
    match value {
        Contamination::Auto => "auto".into_py(py),
        Contamination::Fixed(v) => (*v).into_py(py),
    }
}

#[pymodule]
fn aiwaf_rust(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(validate_headers, m)?)?;
    m.add_function(wrap_pyfunction!(validate_headers_with_config, m)?)?;
    m.add_function(wrap_pyfunction!(extract_features, m)?)?;
    m.add_function(wrap_pyfunction!(extract_features_batch_with_state, m)?)?;
    m.add_function(wrap_pyfunction!(finalize_feature_state, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_recent_behavior, m)?)?;
    m.add_class::<IsolationForest>()?;
    Ok(())
}
