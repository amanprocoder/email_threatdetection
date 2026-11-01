import { useState } from "react";
import "./App.css";

function App() {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeEmail = async () => {
    if (!email.trim()) {
      setError("Please enter email text first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL}/predict`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Analysis failed");
      }

      setResult(data);
    } catch (err) {
      setError(
        "Cannot connect to Flask. Please check whether the backend is running."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>🛡️ ThreatGuard AI</h2>
        <p className="subtitle">EMAIL SECURITY PLATFORM</p>

        <nav>
          <div className="nav-item active">▣ Dashboard</div>
          <div className="nav-item">✉ Email Detection</div>
          <div className="nav-item">↗ URL Analysis</div>
          <div className="nav-item">◎ IP Geolocation</div>
          <div className="nav-item">⌕ Email Forensics</div>
          <div className="nav-item">◷ Analysis History</div>
          <div className="nav-item">▤ Security Reports</div>
        </nav>

        <div className="sidebar-footer">
          <span className="online-dot"></span>
          System Interface
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>Email Threat Detection</h1>
            <p>AI-powered email security and threat intelligence</p>
          </div>
          <div className="system-status">
            <span className="online-dot"></span>
            Dashboard Online
          </div>
        </header>

        <section className="stats">
          <div className="stat-card">
            <span>Total Emails Analyzed</span>
            <h2>--</h2>
            <small>Session statistics coming soon</small>
          </div>

          <div className="stat-card">
            <span>Threats Detected</span>
            <h2>--</h2>
            <small>Analysis history not connected</small>
          </div>

          <div className="stat-card">
            <span>ML Model Accuracy</span>
            <h2>97.42%</h2>
            <small>Training test-set accuracy</small>
          </div>
        </section>

        <section className="analysis-card">
          <h2>✉ Analyze an Email</h2>
          <p>
            Paste email content below to check for potential phishing threats.
          </p>

          <textarea
            placeholder="Paste the complete email message here..."
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

          <button onClick={analyzeEmail} disabled={loading}>
            {loading ? "Analyzing..." : "🔍 Analyze Email"}
          </button>

          {error && <p className="error">{error}</p>}
        </section>

        {result && (
          <section className="result-card">
            <h2>Security Analysis Report</h2>

            <div className="result-row">
              <span>Classification</span>
              <strong
                className={
                  result.prediction.toLowerCase().includes("phishing")
                    ? "danger"
                    : "safe"
                }
              >
                {result.prediction}
              </strong>
            </div>

            <div className="result-row">
              <span>Model Confidence</span>
              <strong>{result.confidence}%</strong>
            </div>

            <div className="result-row">
              <span>Analysis Status</span>
              <strong>{result.message}</strong>
            </div>

            <h3>Possible Warning Signs</h3>
            {result.warning_signs?.length > 0 ? (
              <ul>
                {result.warning_signs.map((warning, index) => (
                  <li key={index}>
                  <strong>{warning.category}:</strong> {warning.details}
                    </li>
                    ))}
              </ul>
            ) : (
              <p>No warning signs detected by basic checks.</p>
            )}

            <h3>URLs Found</h3>
            {result.urls_found?.length > 0 ? (
              <ul>
                {result.urls_found.map((url, index) => (
                  <li key={index}>{url}</li>
                ))}
              </ul>
            ) : (
              <p>No URLs found in this email.</p>
            )}

            <p className="disclaimer">
              This is an automated prediction, not proof that an email is safe
              or malicious. Always verify suspicious messages independently.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;