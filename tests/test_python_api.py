import aiwaf_rust


def test_validate_headers():
    reason = aiwaf_rust.validate_headers({
        "HTTP_USER_AGENT": "Mozilla/5.0",
        "HTTP_ACCEPT": "text/html",
        "HTTP_ACCEPT_LANGUAGE": "en-US",
        "HTTP_ACCEPT_ENCODING": "gzip, deflate",
        "HTTP_CONNECTION": "keep-alive",
    })
    assert reason is None


def test_validate_headers_with_config():
    reason = aiwaf_rust.validate_headers_with_config(
        {
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "HTTP_ACCEPT_LANGUAGE": "en-US",
            "HTTP_ACCEPT_ENCODING": "gzip, deflate",
            "HTTP_CONNECTION": "keep-alive",
        },
        ["HTTP_USER_AGENT"],
        0,
    )
    assert reason is None


def test_extract_features_and_state():
    records = [
        {
            "ip": "1.2.3.4",
            "path_lower": "/wp-admin",
            "path_len": 9,
            "timestamp": 10.0,
            "response_time": 0.03,
            "status_idx": 3,
            "kw_check": True,
            "total_404": 5,
        }
    ]
    feats = aiwaf_rust.extract_features(records, ["wp"])
    assert len(feats) == 1
    assert feats[0]["kw_hits"] >= 1

    batch = aiwaf_rust.extract_features_batch_with_state(records, ["wp"], None)
    assert "features" in batch
    assert "state" in batch


def test_analyze_recent_behavior():
    entries = [
        {
            "path_lower": "/wp-admin",
            "timestamp": 1.0,
            "status": 404,
            "kw_check": True,
        }
        for _ in range(12)
    ]
    res = aiwaf_rust.analyze_recent_behavior(entries, ["wp"])
    assert res is not None
    assert res["should_block"] in (True, False)


def test_isolation_forest_roundtrip():
    forest = aiwaf_rust.IsolationForest(
        n_estimators=10,
        max_samples=8,
        contamination="auto",
        max_features=1.0,
        bootstrap=False,
        random_state=7,
        warm_start=False,
    )
    forest.fit([[0.0], [1.0], [2.0], [10.0]])
    score = forest.anomaly_score([10.0])
    assert score >= 0.0

    state = forest.to_json()
    forest2 = aiwaf_rust.IsolationForest.from_json(state)
    forest2.retrain([[0.1], [0.2], [0.3], [9.5]])
    preds = forest2.predict([[0.1], [9.5]])
    assert len(preds) == 2
