
import pandas as pd
from urllib.parse import urlsplit
from ucimlrepo import fetch_ucirepo
from tldextract import TLDExtract

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

print("Loading dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"].fillna("").astype(str).str.strip()
labels = dataset.data.targets["label"].astype(int)

valid = urls.str.len() > 0
urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)

extract = TLDExtract(suffix_list_urls=())

def registered_domain(url):
    try:
        value = url if "://" in url else "https://" + url
        host = urlsplit(value).hostname
        if not host:
            return ""
        result = extract(host.lower())
        return ".".join(part for part in [result.domain, result.suffix] if part)
    except ValueError:
        return ""

domains = urls.map(registered_domain)

# Exclude URLs for which a registered domain could not be extracted.
valid = domains.str.len() > 0
urls = urls[valid].reset_index(drop=True)
labels = labels[valid].reset_index(drop=True)
domains = domains[valid].reset_index(drop=True)

print("Usable URLs:", len(urls))
print("Unique registered domains:", domains.nunique())

# Split by registered domain, so a domain cannot occur in both sets.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(urls, labels, groups=domains)
)

X_train, X_test = urls.iloc[train_idx], urls.iloc[test_idx]
y_train, y_test = labels.iloc[train_idx], labels.iloc[test_idx]

print("Training URLs:", len(X_train))
print("Testing URLs:", len(X_test))
print("Train/test domain overlap:", len(
    set(domains.iloc[train_idx]) & set(domains.iloc[test_idx])
))

model = Pipeline([
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

print("\nTraining on training domains...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)
phishing_index = list(model.classes_).index(0)

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0,
))

print("Confusion matrix (rows/columns: phishing, legitimate):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print("ROC-AUC:", round(
    roc_auc_score(y_test, probabilities[:, phishing_index] * -1 + 1)
    if False else roc_auc_score(
        y_test, probabilities[:, list(model.classes_).index(1)]
    ),
    4,
))
