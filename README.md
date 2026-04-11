# aiwaf-rust

`aiwaf-rust` is a Rust core with Python and WebAssembly bindings that provides fast request-header, behavior heuristics, and isolation forest anomaly scoring for WAF-style detection.

- PyPI package: `aiwaf-rust`
- Python import: `aiwaf_rust`
- Built with: `PyO3` + `maturin`
- WASM package: `aiwaf-wasm` (npm)
- Built with: `wasm-bindgen` + `wasm-pack`
- Version: `0.1.3`

## Features

- Header validation with configurable required headers and scoring
- Request feature extraction for downstream detection logic
- Recent behavior analysis for suspicious scanning patterns
- Isolation Forest anomaly detection with sklearn-style API
- Cross-platform wheel publishing (Linux, macOS, Windows)
- WASM build for browser and bundler targets

## Installation

### From PyPI

```bash
pip install aiwaf-rust
```

### Local development install

```bash
pip install maturin
maturin develop
```

## Python API

```python
import aiwaf_rust

# 1) Basic header validation
reason = aiwaf_rust.validate_headers({
    "HTTP_USER_AGENT": "Mozilla/5.0",
    "HTTP_ACCEPT": "text/html"
})

# 2) Configurable validation
reason = aiwaf_rust.validate_headers_with_config(
    {
        "HTTP_USER_AGENT": "Mozilla/5.0",
        "HTTP_ACCEPT": "text/html"
    },
    ["HTTP_USER_AGENT", "HTTP_ACCEPT"],
    3,
)

# 3) Feature extraction
features = aiwaf_rust.extract_features(
    {
        "ip": "1.2.3.4",
        "path_lower": "/wp-admin",
        "path_len": 9,
        "timestamp": 1700000000.0,
        "response_time": 0.03,
        "status_idx": 3,
        "kw_check": True,
        "total_404": 5,
    },
    []
)

# 4) Behavior analysis
analysis = aiwaf_rust.analyze_recent_behavior([], "1.2.3.4")

# 5) Isolation Forest
forest = aiwaf_rust.IsolationForest(
    n_estimators=100,
    max_samples="auto",
    contamination="auto",
    max_features=1.0,
    bootstrap=False,
    random_state=42,
    warm_start=False,
)
forest.fit([[0.1, 1.0], [0.2, 1.1], [9.0, 9.0]])
score = forest.anomaly_score([9.0, 9.0])
labels = forest.predict([[0.1, 1.0], [9.0, 9.0]])

# Save and load
state = forest.to_json()
forest2 = aiwaf_rust.IsolationForest.from_json(state)
forest2.retrain([[0.15, 1.05], [0.25, 1.2]])
```

## WASM API (JS)

Install from npm:

```bash
npm install aiwaf-wasm
```

Usage (bundler target):

```js
import init, { IsolationForest, validate_headers, extract_features } from "aiwaf-wasm";

await init();

const reason = validate_headers({
  HTTP_USER_AGENT: "Mozilla/5.0",
  HTTP_ACCEPT: "text/html",
});

const feats = extract_features([
  {
    ip: "1.2.3.4",
    path_lower: "/wp-admin",
    path_len: 9,
    timestamp: 1700000000.0,
    response_time: 0.03,
    status_idx: 3,
    kw_check: true,
    total_404: 5,
  },
], []);

const forest = new IsolationForest({
  n_estimators: 100,
  max_samples: "auto",
  contamination: "auto",
  max_features: 1.0,
  bootstrap: false,
  random_state: 42,
  warm_start: false,
});
forest.fit([[0.1, 1.0], [0.2, 1.1], [9.0, 9.0]]);
const score = forest.anomaly_score([9.0, 9.0]);
const state = forest.to_json();
const forest2 = IsolationForest.from_json(state);
forest2.retrain([[0.15, 1.05], [0.25, 1.2]]);
```

## Isolation Forest Details

Isolation Forest isolates points by randomly choosing a feature and a split value between that feature’s min and max. The number of splits required to isolate a point is its path length. Anomalies tend to have shorter path lengths because they are easier to isolate.

Key mechanics:

- A tree is built by selecting a random split value for each candidate feature at a node and choosing the split with the best variance reduction (ExtraTreeRegressor-style random splitter).
- The tree stops when it reaches `max_depth = ceil(log2(max_samples))` or the node has 0 or 1 samples, or all values are identical for the chosen feature.
- Path length for a point is the depth at which it lands, plus the average path length adjustment for the leaf size.

Scoring:

- For each tree, compute the path length `h(x)`.
- Average across trees: `E[h(x)]`.
- Convert to anomaly score: `s(x) = 2 ^ (-E[h(x)] / c(max_samples))`.
- `c(n)` is the average path length of an unsuccessful search in a binary search tree:
  - `c(n) = 0` for `n <= 1`
  - `c(n) = 1` for `n = 2`
  - otherwise `c(n) = 2 * (ln(n-1) + 0.5772156649) - 2*(n-1)/n`

Interpretation:

- Higher `s(x)` means more anomalous.
- `score_samples` returns the opposite of the anomaly score (higher = more normal), like sklearn.
- `decision_function = score_samples - offset_`.
- `predict` returns `1` for inliers and `-1` for outliers.
- With `contamination="auto"`, `offset_ = -0.5`. With numeric contamination, `offset_` is set to the percentile of training scores.

Retraining:

- With `warm_start=True`, `fit` appends new trees up to `n_estimators`.
- `retrain` always appends trees, preserving existing ones.

## Build and Test

```bash
# Run Rust tests
cargo test

# Build Python wheel locally
maturin build --release --out dist

# Build source distribution
maturin sdist --out dist

# Build WASM package
cd crates/aiwaf_wasm
wasm-pack build --release --target bundler
```

## Publishing

Publishing is handled by GitHub Actions using trusted publishing.

Workflow: `.github/workflows/publish.yml`

Trigger conditions:
- `release.published`
- `workflow_dispatch`

The workflow builds:
- Wheels for Python `3.8` to `3.12` on `ubuntu-latest`, `macos-latest`, `windows-latest`
- One source distribution (`sdist`)

Then it publishes to PyPI using:
- `pypa/gh-action-pypi-publish@release/v1`
- OIDC (`id-token: write`)

## Compatibility Policy

`aiwaf-rust` and `aiwaf` should be versioned together when possible.

Recommended policy:
- Match `major.minor` between `aiwaf` and `aiwaf-rust`
- Use patch versions independently for bug fixes
- Document compatibility here when versions diverge

| aiwaf | aiwaf-rust |
| --- | --- |
| 0.1.x | 0.1.x |

## Development Notes

- Module name in Rust and Python is `aiwaf_rust`
- `pyproject.toml` is the source of Python package metadata
- `Cargo.toml` is the source of Rust crate metadata

## License

MIT. See `LICENSE`.
