# 🛡️ PhishGuard AI

**An experimental machine-learning system for phishing URL risk assessment.**

PhishGuard AI analyzes the text and structure of a URL to identify patterns that may be associated with phishing. It combines a machine-learning model with URL-based risk indicators in a web dashboard.

> **Disclaimer:** This is an experimental project, not a production-grade security tool. Predictions can be incorrect. A low risk score does not guarantee that a website is safe, and a high score does not prove that it is malicious.

## ✨ Features

- **ML-based URL analysis:** Classifies submitted URLs as `Phishing-like` or `Legitimate-like`.
- **Phishing risk score:** Displays the model's estimated phishing score.
- **URL breakdown:** Shows the protocol, hostname, path, query parameter count, and HTTPS status.
- **Structural risk indicators:** Highlights potentially suspicious patterns such as IP-based hosts, unusual hostname structures, missing HTTPS, and sensitive-action wording.
- **Scan history:** Keeps recent scan results during the current browser session.
- **Filtering and sorting:** Filter results by prediction and sort by time or risk score.
- **REST API:** Uses FastAPI to connect the frontend to the machine-learning model.
- **Responsive dashboard:** Provides a clean interface for analyzing URLs.

## 🧰 Tech Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite, JavaScript |
| UI icons | Lucide React |
| Backend | Python, FastAPI |
| Machine learning | Scikit-learn, TF-IDF, Logistic Regression |
| Dataset | UCI PhiUSIIL Phishing URL dataset |
| API testing | FastAPI Swagger UI |

## 🏗️ Project Structure

```text
PhishGuard-AI/
├── backend/
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── package.json
│   └── index.html
├── train_model.py
├── detector.py
├── phishing_model.joblib
├── check_domains.py
├── evaluate_domains.py
└── README.md
```

## ⚙️ Getting Started

### Prerequisites

Install the following before running the project:

- Python
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone https://github.com/skanda545/PhishGuard-AI.git
```

**Note:** Replace the repository URL above with your PhishGuard AI repository URL once you create its GitHub repository.

Navigate into the project folder:

```bash
cd PhishGuard-AI
```

### 2. Set up the Python backend

From the project root, create and activate a virtual environment:

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the backend dependencies:

```bash
python -m pip install -r backend/requirements.txt
```

Start the API:

```bash
python -m uvicorn backend.main:app --reload
```

The backend should be available at:

- API: http://127.0.0.1:8000
- Interactive API documentation: http://127.0.0.1:8000/docs

Keep this terminal running.

### 3. Set up the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, usually:

http://localhost:5173

Keep the frontend terminal running while using the application.

### Important

The trained model file `phishing_model.joblib` must be present in the project root. The backend and frontend must both be running for URL analysis to work.

## 🔌 API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API welcome message and status |
| GET | `/health` | Health check |
| POST | `/analyze` | Analyze a submitted URL |

Example request to `/analyze`:

```json
{
  "url": "https://example.com/login"
}
```

Use the interactive documentation at `/docs` to test the API and inspect the response format.

## 🧠 How It Works

1. The user submits a URL through the dashboard.
2. The frontend sends the URL to the FastAPI backend.
3. The backend validates and analyzes the URL using the trained machine-learning model.
4. The model returns a classification and a phishing score.
5. The dashboard displays the prediction, URL breakdown, structural indicators, and scan history.

The model uses character-level TF-IDF features and Logistic Regression to learn patterns in URL text.

## 🔒 Limitations and Responsible Use

- The application analyzes URL text; it does not visit the submitted website.
- It does not verify live website content, domain reputation, certificates, or current threat intelligence.
- Structural indicators are heuristics, not proof of a phishing attack.
- Dataset labels and patterns may not represent every real-world website.
- The displayed score is a model output, not a verified real-world probability of maliciousness.
- Do not rely on this prototype alone to make security decisions.

## 🚀 Future Improvements

- Integrate trusted domain reputation and threat-intelligence services.
- Improve generalization using more diverse, carefully validated datasets.
- Add explainable predictions showing which URL patterns influenced a result.
- Introduce automated tests and API error-handling improvements.
- Explore safe, controlled evaluation against updated phishing datasets.
- Deploy the frontend and backend for public demonstration.

## 👨‍💻 Author

**Skanda C**

GitHub: [@skanda545](https://github.com/skanda545)

---

*Built as a machine-learning and web-development project to explore phishing URL detection and responsible AI-assisted security analysis.*