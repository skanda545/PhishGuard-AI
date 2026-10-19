
import gc
import joblib
import pandas as pd

from pathlib import Path
from urllib.parse import urlsplit
from ucimlrepo import fetch_ucirepo
from tldextract import TLDExtract

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"


def build_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=2,
            max_features=150000,
            lowercase=True,
            sublinear_tf=True,
        )),
        ("classifier", LogisticRegression(
            max_iter=500,
            class_weight="balanced",
            random_state=42,
        )),
    ])


def get_registered_domain(url, extractor):
    try:
        value = url if "://" in url else "https://" + url
        hostname = urlsplit(value).hostname

        if not hostname:
            return ""

        result = extractor(hostname.lower())

        return ".".join(
            part for part in (result.domain, result.suffix) if part
        )
    except ValueError:
        return ""


print("Loading dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"].fillna("").astype(str).str.strip()
labels = dataset.data.targets["label"].astype(int)

valid = urls.str.len() > 0
urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)

print("Dataset size:", len(urls))
print("Labels: 0 = phishing, 1 = legitimate")

extractor = TLDExtract(suffix_list_urls=())
domains = urls.map(lambda url: get_registered_domain(url, extractor))

valid = domains.str.len() > 0
urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)
domains = domains[valid].reset_index(drop=True)

print("Unique registered domains:", domains.nunique())

# Evaluate using domains completely excluded from training.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(urls, labels, groups=domains)
)

X_train = urls.iloc[train_idx]
y_train = labels.iloc[train_idx]
X_test = urls.iloc[test_idx]
y_test = labels.iloc[test_idx]

overlap = set(domains.iloc[train_idx]) & set(domains.iloc[test_idx])
print("Train/test domain overlap:", len(overlap))

if overlap:
    raise RuntimeError("Domain leakage detected. Evaluation stopped.")

print("\nTraining evaluation model...")
evaluation_model = build_model()
evaluation_model.fit(X_train, y_train)

predictions = evaluation_model.predict(X_test)
probabilities = evaluation_model.predict_proba(X_test)
legitimate_index = list(evaluation_model.classes_).index(1)

print("\nDomain-separated classification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))

print("Confusion matrix (phishing, legitimate):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print(
    "ROC-AUC:",
    round(roc_auc_score(y_test, probabilities[:, legitimate_index]), 4),
)

# Release the evaluation model before fitting the final model.
del evaluation_model
gc.collect()

# Train the deployed model on all available labelled URLs.
print("\nTraining final model on the full dataset...")
final_model = build_model()
final_model.fit(urls, labels)

joblib.dump(
    {
        "model": final_model,
        "type": "url_text",
    },
    MODEL_PATH,
)

print("\nFinal model saved to:", MODEL_PATH)
print("Training complete!")
print("Your detector can now load the updated model.")
