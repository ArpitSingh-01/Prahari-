"""Offline ML training: rule-labeled risk classifier + IsolationForest.

Labels are derived from the deterministic rule engine (NIST/CERT-In seeded),
so the classifier learns published guidance rather than opinion. Models and
a published metrics file (ml/models/metrics.json) are committed — the
Render service never trains at runtime, and the model card in the UI reads
the same committed metrics.

Usage:  python ml/train.py
"""
from __future__ import annotations

import glob
import json
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import cross_val_score, train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, BACKEND)

from app.pipeline.features import FEATURE_NAMES, to_vector          # noqa: E402
from app.pipeline.runner import analyze_pcap                        # noqa: E402

PCAP_GLOBS = [
    os.path.join(BACKEND, "fixtures", "pcaps", "train", "*.pcap"),
    os.path.join(BACKEND, "fixtures", "pcaps", "*.pcap"),
]
MODEL_DIR = os.path.join(HERE, "models")
LABEL_NAMES = ["critical", "high", "medium", "low"]


def label_of(session_findings: list[dict]) -> int:
    sev = {f["severity"] for f in session_findings}
    if "critical" in sev:
        return 0
    if "high" in sev:
        return 1
    if "medium" in sev:
        return 2
    return 3


def load_corpus():
    X, y, clean_X = [], [], []
    seen = set()
    for pattern in PCAP_GLOBS:
        for path in sorted(glob.glob(pattern)):
            if "train/" not in path.replace("\\", "/") and path in seen:
                continue
            seen.add(path)
            result = analyze_pcap(open(path, "rb").read())
            for sess, feat in zip(result["sessions"], result["features"]):
                vec = to_vector(feat)
                fnd = sess.findings
                X.append(vec)
                y.append(label_of(fnd))
                if not fnd:
                    clean_X.append(vec)
    return np.array(X), np.array(y), np.array(clean_X)


def _per_class_metrics(y_true, y_pred) -> dict:
    out = {"macro": {
        "precision": round(float(precision_score(y_true, y_pred, average="macro",
                                                 zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, average="macro",
                                           zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, average="macro",
                                   zero_division=0)), 4),
    }}
    for i, name in enumerate(LABEL_NAMES):
        tp = int(((y_pred == i) & (y_true == i)).sum())
        fp = int(((y_pred == i) & (y_true != i)).sum())
        fn = int(((y_pred != i) & (y_true == i)).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out[name] = {"precision": round(prec, 4), "recall": round(rec, 4),
                     "f1": round(f1, 4), "support": int((y_true == i).sum())}
    return out


def main() -> None:
    X, y, clean_X = load_corpus()
    print("corpus: %d sessions (%d clean)" % (len(X), len(clean_X)))
    print("label distribution:", {LABEL_NAMES[i]: int((y == i).sum()) for i in range(4)})

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    clf = GradientBoostingClassifier(random_state=42, n_estimators=200,
                                     max_depth=3)
    acc = cross_val_score(clf, X, y, cv=5).mean()
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)
    test_acc = accuracy_score(y_te, y_pred)
    print("risk classifier 5-fold accuracy: %.3f" % acc)
    print("risk classifier holdout accuracy: %.3f (n=%d)" % (test_acc, len(y_te)))

    # anomaly baseline: fit on clean sessions; fall back to all if too few.
    # Low contamination -> threshold sits deep in the healthy distribution,
    # so anything notably worse than healthy flags at inference time.
    base = clean_X if len(clean_X) >= 15 else X
    contamination = 0.05
    iso = IsolationForest(random_state=42, contamination=contamination)
    iso.fit(base)
    flags_all = (iso.predict(X) == -1).sum()
    flags_clean = (iso.predict(clean_X) == -1).sum() if len(clean_X) else 0
    print("isolation forest: %d/%d sessions flagged anomalous "
          "(contamination %.2f, baseline %d clean sessions)"
          % (flags_all, len(X), contamination, len(base)))
    print("isolation forest flag rate on clean baseline: %d/%d"
          % (flags_clean, len(clean_X)))

    # feature baseline stats for z-score explanations at runtime
    mean = base.mean(axis=0).tolist()
    std = [s if s > 1e-9 else 1.0 for s in base.std(axis=0).tolist()]

    cm = confusion_matrix(y_te, y_pred, labels=list(range(len(LABEL_NAMES))))
    metrics = {
        "schema": "prahari.modelcard/v1",
        "risk_classifier": {
            "model": "GradientBoostingClassifier",
            "n_estimators": 200,
            "features": len(FEATURE_NAMES),
            "train_size": int(len(X_tr)),
            "test_size": int(len(X_te)),
            "cv_accuracy": round(float(acc), 4),
            "holdout_accuracy": round(float(test_acc), 4),
            "per_class": _per_class_metrics(y_te, y_pred),
            "confusion_matrix": {
                "labels": LABEL_NAMES,
                "matrix": cm.tolist(),
            },
            "label_distribution": {LABEL_NAMES[i]: int((y == i).sum())
                                   for i in range(len(LABEL_NAMES))},
            "labeling": "Labels derived from the deterministic rule engine "
                        "(NIST SP 800-52r2 / RFC 8996 / BSI TR-02102 / CERT-In) "
                        "over a synthetic pcap corpus — the classifier learns "
                        "published guidance, not opinion.",
        },
        "anomaly_detector": {
            "model": "IsolationForest",
            "contamination": contamination,
            "baseline_sessions": int(len(base)),
            "flag_rate_all": round(float(flags_all) / len(X), 4),
            "flag_rate_clean_baseline": round(
                float(flags_clean) / len(clean_X), 4) if len(clean_X) else None,
            "corpus_sessions": int(len(X)),
            "training": "Unsupervised: fitted only on clean sessions to learn "
                        "a healthy baseline; deviations explained via "
                        "per-feature z-scores.",
        },
        "corpus": {
            "sessions": int(len(X)),
            "clean_sessions": int(len(clean_X)),
            "source": "synthetic pcap corpus (scripts/gen_traffic.py), "
                      "rule-engine labeled",
        },
    }

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES,
                 "label_names": LABEL_NAMES, "cv_accuracy": round(float(acc), 4),
                 "n_train": len(X)},
                os.path.join(MODEL_DIR, "risk_clf.joblib"))
    joblib.dump({"model": iso, "feature_names": FEATURE_NAMES,
                 "baseline_mean": mean, "baseline_std": std,
                 "contamination": contamination},
                os.path.join(MODEL_DIR, "anomaly_iforest.joblib"))
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)
    print("saved ->", os.path.abspath(MODEL_DIR))


if __name__ == "__main__":
    main()
