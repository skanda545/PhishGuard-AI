
import { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Clock3,
  Trash2,
  ExternalLink,
  Activity,
  Globe,
  ChevronRight,
  LoaderCircle,
  Info,
} from "lucide-react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function getHost(value) {
  try {
    return new URL(
      value.match(/^https?:\/\//i) ? value : `https://${value}`
    ).hostname;
  } catch {
    return value;
  }
}

function getURLIndicators(value) {
  try {
    const normalized = /^https?:\/\//i.test(value)
      ? value
      : `https://${value}`;

    const parsed = new URL(normalized);
    const hostname = parsed.hostname;
    const fullURL = parsed.href;
    const indicators = [];

    const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isIPv6 = hostname.includes(":");
    const labels = hostname.split(".");
    const suspiciousTerms =
      /login|signin|verify|account|password|wallet|payment|update|secure/i;

    if (isIPv4 || isIPv6) {
      indicators.push({
        title: "IP-address host",
        detail: "The hostname is an IP address rather than a conventional domain.",
        level: "warning",
      });
    }

    if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
      indicators.push({
        title: "Internationalized hostname",
        detail: "The hostname contains encoded international characters. Check for lookalike characters.",
        level: "warning",
      });
    }

    if (labels.length >= 5) {
      indicators.push({
        title: "Many subdomain levels",
        detail: "This hostname has several dot-separated levels. Inspect the registered domain carefully.",
        level: "warning",
      });
    }

    if (parsed.protocol === "http:") {
      indicators.push({
        title: "No HTTPS",
        detail: "This URL uses HTTP, so the connection does not use HTTPS encryption.",
        level: "warning",
      });
    }

    if (parsed.username || parsed.password || parsed.host.includes("@")) {
      indicators.push({
        title: "URL contains user information",
        detail: "User information or an @ symbol appears in the URL authority. Check which hostname the browser will open.",
        level: "warning",
      });
    }

    if (suspiciousTerms.test(`${hostname}${parsed.pathname}`)) {
      indicators.push({
        title: "Sensitive-action wording",
        detail: "The hostname or path contains terms commonly used on sign-in or account-related pages. Legitimate sites use these too.",
        level: "caution",
      });
    }

    if (fullURL.length > 100) {
      indicators.push({
        title: "Long URL",
        detail: `This URL contains ${fullURL.length} characters. Length alone does not indicate phishing.`,
        level: "caution",
      });
    }

    if (indicators.length === 0) {
      indicators.push({
        title: "No listed structural indicators",
        detail: "These simple checks found no listed patterns. This does not establish that the URL is safe.",
        level: "neutral",
      });
    }

    return indicators;
  } catch {
    return [{
      title: "Unable to inspect URL",
      detail: "The URL structure could not be parsed.",
      level: "neutral",
    }];
  }
}

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("All");
const [sortBy, setSortBy] = useState("newest");
  async function analyzeURL(event) {
    event.preventDefault();
    if (!url.trim() || loading) return;

    setLoading(true);
    setError("");
    setResult(null);
    setSelected(null);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to analyze this URL.");
      }

      const item = {
        ...data,
        id: `${Date.now()}-${Math.random()}`,
        scannedAt: new Date().toLocaleTimeString(),
      };

      setResult(item);
      setHistory((previous) => [item, ...previous]);
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot connect to the API. Make sure the FastAPI backend is running at http://127.0.0.1:8000."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  
const visibleHistory = history
  .filter((item) => {
    if (filter === "All") return true;
    if (filter === "Phishing-like") return item.warning;
    return !item.warning;
  })
  .sort((a, b) => {
    if (sortBy === "highest") {
      return b.phishing_probability - a.phishing_probability;
    }
    if (sortBy === "lowest") {
      return a.phishing_probability - b.phishing_probability;
    }
    if (sortBy === "oldest") {
      return Number(a.id.split("-")[0]) - Number(b.id.split("-")[0]);
    }
    return Number(b.id.split("-")[0]) - Number(a.id.split("-")[0]);
  });


  const active = selected || result;
  const risk = active
  ? (active.phishing_probability * 100).toFixed(2)
  : null;

const parsedURL = active
  ? (() => {
      try {
        return new URL(
          active.url.match(/^https?:\/\//i)
            ? active.url
            : `https://${active.url}`
        );
      } catch {
        return null;
      }
    })()
  : null;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="PhishGuard AI home">
          <span className="brand-icon"><ShieldCheck size={23} /></span>
          <span>
            <strong>PhishGuard</strong>
            <small>AI SECURITY LAB</small>
          </span>
        </a>

        <div className="nav-label">WORKSPACE</div>
        <div className="nav-item active"><Activity size={18} /> URL analysis</div>
        <div className="nav-item"><Clock3 size={18} /> Scan history <span className="nav-count">{history.length}</span></div>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <div><strong>Local API</strong><small>Development environment</small></div>
          <span className="live-dot" />
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>URL analysis</strong></div>
          <div className="top-right"><span className="environment">LOCAL ENVIRONMENT</span><span className="avatar">SC</span></div>
        </header>

        <div className="content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span /> THREAT ASSESSMENT</div>
              <h1>URL Security Analysis</h1>
              <p>Inspect URL patterns for indicators commonly associated with phishing.</p>
            </div>
            <div className="model-chip"><span className="model-dot" /> ML model <span className="chip-divider" /> TF-IDF + Logistic Regression</div>
          </section>

          <section className="scan-card">
            <div className="section-title"><div className="section-icon"><Search size={18} /></div><div><h2>Analyze a URL</h2><p>Enter a web address to run a model assessment.</p></div></div>
            <form onSubmit={analyzeURL}>
              <label htmlFor="url-input">URL or web address</label>
              <div className="input-row">
                <Globe className="input-globe" size={19} />
                <input
                  id="url-input"
                  type="text"
                  placeholder="https://example.com/login"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  required
                />
                <button className="analyze-button" type="submit" disabled={loading || !url.trim()}>
                  {loading ? <><LoaderCircle className="spin" size={17} /> Analyzing</> : <><Search size={17} /> Analyze URL</>}
                </button>
              </div>
            </form>
            <div className="input-foot"><span>HTTP and HTTPS URLs supported</span><span> <ShieldCheck size={14} /> URL text analysis only</span></div>
            {error && <div className="error-message"><ShieldAlert size={17} /> {error}</div>}
          </section>

          {active ? (
            <section className="result-card">
              <div className="result-header">
                <div><div className="eyebrow">LATEST ASSESSMENT</div><h2>Analysis result</h2></div>
                <span className={`result-badge ${active.warning ? "danger" : "safe"}`}>
                  {active.warning ? <ShieldAlert size={15} /> : <ShieldCheck size={15} />}
                  {active.prediction}
                </span>
              </div>
              <div className="result-grid">
                <div className="risk-panel">
                  <span className="metric-label">MODEL PHISHING SCORE</span>
                  <div className={`risk-number ${active.warning ? "risk-high" : ""}`}>{risk}<span>%</span></div>
                  <div className="risk-track"><div className={`risk-fill ${active.warning ? "fill-high" : ""}`} style={{ width: `${risk}%` }} /></div>
                  <p>{active.warning ? "The model identified patterns associated with phishing." : "The model found fewer phishing-associated URL patterns."}</p>
                </div>
                <div className="details-panel">
                  <div className="detail-row"><span>Analyzed hostname</span><strong>{getHost(active.url)}</strong></div>
                  <div className="detail-row"><span>Full URL</span><strong className="url-detail">{active.url}</strong></div>
                  <div className="detail-row"><span>Assessment type</span><strong>Machine learning</strong></div>
                  <div className="detail-row"><span>Website visited</span><strong>No</strong></div>
                </div>
              </div>
              
{parsedURL && (
  <div className="url-breakdown">
    <div className="breakdown-heading">
      <Globe size={17} />
      <h3>URL breakdown</h3>
    </div>

    <div className="breakdown-grid">
      <div className="breakdown-item">
        <span>Protocol</span>
        <strong>{parsedURL.protocol.replace(":", "").toUpperCase()}</strong>
      </div>

      <div className="breakdown-item">
        <span>Hostname</span>
        <strong>{parsedURL.hostname}</strong>
      </div>

      <div className="breakdown-item">
        <span>Path</span>
        <strong>{parsedURL.pathname || "/"}</strong>
      </div>

      <div className="breakdown-item">
        <span>Query parameters</span>
        <strong>{parsedURL.searchParams.size}</strong>
      </div>

      <div className="breakdown-item">
        <span>HTTPS enabled</span>
        <strong>{parsedURL.protocol === "https:" ? "Yes" : "No"}</strong>
      </div>
    </div>
    <p className="breakdown-caption">
      These are structural URL details, not proof that a website is safe or malicious.
    </p>
  </div>
)}
<div className="indicators-panel">
  <div className="breakdown-heading">
    <ShieldAlert size={17} />
    <h3>URL risk indicators</h3>
  </div>

  <p className="indicators-intro">
    Structural observations from the URL. These are not confirmed threats.
  </p>

  <div className="indicators-list">
    {getURLIndicators(active.url).map((indicator, index) => (
      <div
        className={`indicator-item indicator-${indicator.level}`}
        key={`${indicator.title}-${index}`}
      >
        <span className="indicator-mark">
          {indicator.level === "warning"
            ? "!"
            : indicator.level === "caution"
              ? "•"
              : "i"}
        </span>

        <div>
          <strong>{indicator.title}</strong>
          <p>{indicator.detail}</p>
        </div>
      </div>
    ))}
  </div>
</div>

<div className="result-note"><Info size={17} /><p><strong>Interpret results carefully.</strong> This is an experimental score based on URL text patterns, not a verified probability of attack. The model does not visit the website or check its reputation. A low score does not guarantee a URL is safe.</p></div>
              <div className="result-actions"><button className="text-button" onClick={() => { setUrl(active.url); setSelected(null); }}><Search size={15} /> Recheck URL</button><span>Scanned at {active.scannedAt || "this session"}</span></div>
            </section>
          ) : (
            <section className="empty-state">
              <div className="empty-icon"><ShieldCheck size={28} /></div>
              <h2>Ready to inspect a URL</h2>
              <p>Your analysis results will appear here. Enter a URL above to get started.</p>
              <div className="empty-points"><span><ShieldCheck size={15} /> ML-based assessment</span><span><Activity size={15} /> Instant API response</span><span><Globe size={15} /> No website visit</span></div>
            </section>
          )}

          <section className="history-section">
            <div className="history-heading">
              <div><h2><Clock3 size={19} /> Recent scans</h2><p>URLs analyzed during this session</p></div>
              <div className="history-controls">
                
<select
  value={sortBy}
  onChange={(event) => setSortBy(event.target.value)}
  aria-label="Sort scans"
>
  <option value="newest">Newest first</option>
  <option value="oldest">Oldest first</option>
  <option value="highest">Highest score</option>
  <option value="lowest">Lowest score</option>
</select>

                <select value={filter} onChange={(event) => setFilter(event.target.value)} aria-label="Filter scans">
                  <option>All</option><option>Phishing-like</option><option>Legitimate-like</option>
                </select>
                <button className="clear-button" onClick={() => { setHistory([]); setSelected(null); setResult(null); }} disabled={history.length === 0}><Trash2 size={15} /> Clear</button>
              </div>
            </div>
            {visibleHistory.length === 0 ? (
              <div className="history-empty">{history.length === 0 ? "No scans yet. Your completed analyses will appear here." : "No scans match this filter."}</div>
            ) : (
              <div className="history-table">
                <div className="history-table-head"><span>URL / HOSTNAME</span><span>ASSESSMENT</span><span>SCORE</span><span>TIME</span><span /></div>
                {visibleHistory.map((item) => (
                  <button className={`history-row ${selected?.id === item.id ? "row-selected" : ""}`} key={item.id} onClick={() => { setSelected(item); setResult(item); }}>
                    <span className="history-host"><Globe size={16} /><span><strong>{getHost(item.url)}</strong><small>{item.url}</small></span></span>
                    <span><span className={`mini-badge ${item.warning ? "danger" : "safe"}`}>{item.prediction}</span></span>
                   <strong className={item.warning ? "risk-high" : ""}>
  {(item.phishing_probability * 100).toFixed(2)}%
</strong>
                    <span className="history-time">{item.scannedAt}</span>
                    <ChevronRight size={16} className="row-chevron" />
                  </button>
                ))}
              </div>
            )}
          </section>

          <footer className="footer"><span>PHISHGUARD AI <span className="footer-separator">/</span> STUDENT PROJECT</span><span>Experimental tool · Not a substitute for security software</span></footer>
        </div>
      </main>
    </div>
  );
}

export default App;
