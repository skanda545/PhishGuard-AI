
from urllib.parse import urlsplit

from ucimlrepo import fetch_ucirepo

print("Loading dataset...")
dataset = fetch_ucirepo(id=967)

urls = dataset.data.features["URL"].fillna("").astype(str)
labels = dataset.data.targets["label"].astype(int)

def get_hostname(url):
    try:
        value = url.strip()
        if "://" not in value:
            value = "https://" + value
        return (urlsplit(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

hosts = urls.map(get_hostname)

data = __import__("pandas").DataFrame({
    "hostname": hosts,
    "label": labels
})

data = data[data["hostname"] != ""]

print("\nRows per label:")
print(data["label"].value_counts().sort_index().to_dict())

print("\nUnique hostnames per label:")
print(data.groupby("label")["hostname"].nunique().to_dict())

print("\nMost common hostnames labelled legitimate (1):")
print(
    data[data["label"] == 1]["hostname"]
    .value_counts()
    .head(15)
    .to_string()
)

print("\nMost common hostnames labelled phishing (0):")
print(
    data[data["label"] == 0]["hostname"]
    .value_counts()
    .head(15)
    .to_string()
)
