
import re
import ipaddress
import joblib

from pathlib import Path
from urllib.parse import urlsplit

MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"

saved = joblib.load(MODEL_PATH)
model = saved["model"]


def validate_url(raw_url):
    url = raw_url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if re.search(r"[\s\x00-\x1f]", url):
        raise ValueError("URL contains invalid whitespace.")

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        raise ValueError("Invalid URL or port.")

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not hostname:
        raise ValueError("Invalid URL hostname.")

    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid hostname.")

    if len(hostname) > 253:
        raise ValueError("Hostname is too long.")

    # Return a normalized URL for model input.
    return url


def analyze_url(raw_url):
    url = validate_url(raw_url)

    # The TF-IDF pipeline accepts raw URL strings.
    prediction = int(model.predict([url])[0])
    probabilities = model.predict_proba([url])[0]

    phishing_index = list(model.classes_).index(0)
    phishing_probability = float(probabilities[phishing_index])

    return {
        "url": url,
        "prediction": (
            "Phishing-like" if prediction == 0 else "Legitimate-like"
        ),
        "phishing_probability": round(phishing_probability, 4),
        "warning": prediction == 0,
        "note": (
            "Experimental prediction based on URL text patterns. "
            "This does not verify website safety."
        ),
    }


if __name__ == "__main__":
    print("PhishGuard AI URL Detector")
    print("Type 'exit' to quit.")

    while True:
        try:
            url = input("\nEnter a URL: ").strip()

            if url.lower() == "exit":
                break

            result = analyze_url(url)

            print("\nResult:")
            for key, value in result.items():
                print(f"{key}: {value}")

        except ValueError as error:
            print("Input error:", error)
        except Exception as error:
            print(f"Error: {error}")
