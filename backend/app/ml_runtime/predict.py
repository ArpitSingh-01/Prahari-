"""Runtime ML inference: loads the committed joblib models once, predicts
risk class and anomaly flag per session, and explains anomalies via z-scores
against the training baseline."""
from __future__ import annotations

import os

import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
# app/ml_runtime -> backend/ml/models
MODEL_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "ml", "models"))

_state = {"clf": None, "iso": None}


def _load():
    if _state["clf"] is None:
        try:
            _state["clf"] = joblib.load(os.path.join(MODEL_DIR, "risk_clf.joblib"))
        except FileNotFoundError:
            _state["clf"] = {"model": None}
    if _state["iso"] is None:
        try:
            _state["iso"] = joblib.load(os.path.join(MODEL_DIR, "anomaly_iforest.joblib"))
        except FileNotFoundError:
            _state["iso"] = {"model": None}


def available() -> bool:
    _load()
    return _state["clf"]["model"] is not None and _state["iso"]["model"] is not None


def predict_risk(vector: list[float]) -> tuple[int, str, list[float]]:
    """Returns (label_index, label_name, class_probabilities)."""
    _load()
    clf = _state["clf"]["model"]
    if clf is None:
        return 3, "low", []
    proba = clf.predict_proba([vector])[0]
    idx = int(proba.argmax())
    names = _state["clf"]["label_names"]
    return idx, names[idx], [round(float(p), 4) for p in proba]


def predict_anomaly(vector: list[float], feature_names: list[str]) -> tuple[bool, float, list[dict]]:
    """Returns (is_anomaly, score, top_deviant_features)."""
    _load()
    iso = _state["iso"]["model"]
    if iso is None:
        return False, 0.0, []
    pred = iso.predict([vector])[0]
    score = float(iso.decision_function([vector])[0])
    mean = _state["iso"]["baseline_mean"]
    std = _state["iso"]["baseline_std"]
    zscores = [(n, float(v), max(-99.0, min(99.0, (float(v) - m) / s)))
               for n, v, m, s in zip(feature_names, vector, mean, std)]
    top = sorted(zscores, key=lambda t: -abs(t[2]))[:3]
    explain = [{"feature": n, "value": round(v, 3), "z": round(z, 2)}
               for n, v, z in top]
    return bool(pred == -1), float(score), explain


def model_info() -> dict:
    """Model card: committed bundle metadata + the published metrics file
    (ml/models/metrics.json, written by ml/train.py)."""
    _load()
    info: dict = {}
    if _state["clf"].get("model") is not None:
        info["risk_classifier"] = {
            "cv_accuracy": _state["clf"].get("cv_accuracy"),
            "n_train": _state["clf"].get("n_train"),
        }
    if _state["iso"].get("model") is not None:
        info["anomaly_detector"] = {
            "contamination": _state["iso"].get("contamination"),
        }
    try:
        with open(os.path.join(MODEL_DIR, "metrics.json")) as fh:
            import json
            info["metrics"] = json.load(fh)
    except FileNotFoundError:
        pass
    return info
