import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity, AlertCircle, BookOpen, Check, CheckCircle2, ChevronRight,
  CircleHelp, Code2, FileCode2, FlaskConical, Gauge, KeyRound, LayoutDashboard,
  LoaderCircle, MessageSquareText, Play, RefreshCw, Settings, ShieldCheck,
  Sparkles, TerminalSquare, Wifi, WifiOff, XCircle
} from "lucide-react";
import "./styles.css";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const SAMPLE_RULE = `title: Detect Suspicious Whoami Execution
id: 11111111-1111-4111-8111-111111111111
status: experimental
description: Detect whoami execution from a process creation event.
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: whoami.exe
  condition: selection
`;
const SAMPLE_EVENTS = [
  { Image: "C:\\\\Windows\\\\System32\\\\whoami.exe", ParentImage: "C:\\\\Windows\\\\System32\\\\cmd.exe" },
  { Image: "C:\\\\Windows\\\\System32\\\\notepad.exe", ParentImage: "C:\\\\Windows\\\\explorer.exe" }
];

async function api(path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof payload.detail === "string" ? payload.detail : `Request failed (${response.status})`;
    throw new Error(detail);
  }
  return payload;
}

function App() {
  const [rule, setRule] = useState(SAMPLE_RULE);
  const [eventsText, setEventsText] = useState(JSON.stringify(SAMPLE_EVENTS, null, 2));
  const [health, setHealth] = useState("checking");
  const [busy, setBusy] = useState("");
  const [validation, setValidation] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [aiResult, setAiResult] = useState("");
  const [error, setError] = useState("");
  const [validatedRuns, setValidatedRuns] = useState(0);
  const [eventsTested, setEventsTested] = useState(0);
  const [activeNav, setActiveNav] = useState("Overview");
  const [showSettings, setShowSettings] = useState(false);

  const matches = testResult?.matched_count ?? 0;
  const navItems = [
    { label: "Overview", icon: LayoutDashboard, target: "overview" },
    { label: "Rule validation", icon: ShieldCheck, target: "workbench" },
    { label: "Event testing", icon: FlaskConical, target: "event-results" },
    { label: "Rule library", icon: BookOpen, target: "library", soon: true },
    { label: "AI review", icon: Sparkles, target: "ai-review" }
  ];

  const checkHealth = useCallback(async () => {
    try {
      await api("/health");
      setHealth("online");
    } catch {
      setHealth("offline");
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const onFocus = () => checkHealth();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [checkHealth]);

  const navigate = (item) => {
    if (item.soon) {
      setActiveNav(item.label);
      setError("The persistent rule library is not implemented yet. Your current rule remains in this browser session.");
      return;
    }
    setActiveNav(item.label);
    document.getElementById(item.target)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const validateRule = async () => {
    setBusy("validate");
    setError("");
    setAiResult("");
    try {
      const result = await api("/api/v1/rules/validate", { rule });
      setValidation(result);
      setValidatedRuns((count) => count + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const testEvents = async () => {
    setBusy("test");
    setError("");
    try {
      let parsed;
      try {
        parsed = JSON.parse(eventsText);
      } catch {
        throw new Error("Events must be valid JSON.");
      }
      if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((event) => !event || typeof event !== "object" || Array.isArray(event))) {
        throw new Error("Provide a JSON array containing one or more event objects.");
      }
      const result = await api("/api/v1/rules/test", { rule, events: parsed });
      setTestResult(result);
      setEventsTested((count) => count + result.total_events);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const explainRule = async () => {
    setBusy("explain");
    setError("");
    setAiResult("");
    try {
      const result = await api("/api/v1/rules/explain", {
        rule,
        question: "Explain the rule's intent, detection logic, limitations and likely blind spots."
      });
      setAiResult(result.explanation || "The AI provider returned an empty explanation.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const diagnostics = validation?.diagnostics ?? [];
  const resultRows = testResult?.results ?? [];
  const statusText = health === "online" ? "API connected · local" : health === "offline" ? "API unavailable" : "Connecting to API";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><span /></div>
          <div><div className="brand-name">RuleSentry</div><div className="brand-caption">DETECTION WORKBENCH</div></div>
        </div>

        <div className="nav-group">
          <div className="nav-label">WORKSPACE</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.label} className={`nav-item ${activeNav === item.label ? "active" : ""}`} onClick={() => navigate(item)}>
                <Icon size={17} strokeWidth={1.8} />
                <span>{item.label}</span>
                {item.soon && <span className="soon">SOON</span>}
              </button>
            );
          })}
        </div>

        <div className="nav-group resources">
          <div className="nav-label">RESOURCES</div>
          <a className="nav-item" href={`${API_BASE}/docs`} target="_blank" rel="noreferrer"><BookOpen size={17} /><span>API documentation</span><ChevronRight size={14} className="nav-arrow" /></a>
          <button className={`nav-item ${showSettings ? "active" : ""}`} onClick={() => setShowSettings((value) => !value)}><Settings size={17} /><span>Settings</span></button>
        </div>

        <div className="engine-card">
          <div className="engine-title"><span className={`status-dot ${health === "online" ? "good" : health === "offline" ? "bad" : ""}`} />Local engine</div>
          <div className="engine-note">AI review optional · API key required</div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumbs">WORKSPACE <span>/</span> OVERVIEW</div>
          <div className={`connection-pill ${health}`}>
            {health === "online" ? <Wifi size={14} /> : health === "offline" ? <WifiOff size={14} /> : <LoaderCircle size={14} className="spin" />}
            <span>{statusText}</span>
            <button title="Retry connection" onClick={checkHealth}><RefreshCw size={12} /></button>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <h1>Detection engineering</h1>
            <p>Validate Sigma-style rules. Test events. Understand every result.</p>
          </div>
        </section>

        {showSettings && (
          <section className="settings-panel">
            <div><strong>Connection settings</strong><p>Dashboard API base URL: <code>{API_BASE || "same origin / Vite proxy"}</code></p><p>For a separate API host, set <code>VITE_API_BASE_URL</code> before building the frontend.</p></div>
            <button className="icon-button" onClick={() => setShowSettings(false)} aria-label="Close settings"><XCircle size={18} /></button>
          </section>
        )}

        <section className="stats-grid" aria-label="Workspace statistics">
          <StatCard label="RULES VALIDATED" value={validatedRuns} note="this session" icon={ShieldCheck} />
          <StatCard label="EVENTS TESTED" value={eventsTested} note="sample events" icon={Activity} />
          <StatCard label="MATCHES" value={matches} note="in latest run" icon={CheckCircle2} />
          <div className="stat-card engine-stat">
            <div className="stat-label">ENGINE STATUS</div>
            <div className="engine-value"><span className={`status-dot ${health === "online" ? "good" : health === "offline" ? "bad" : ""}`} />{health === "online" ? "Ready" : health === "offline" ? "Offline" : "Checking"}</div>
            <span className="stat-note">deterministic core</span>
          </div>
        </section>

        {error && <div className="alert-banner"><AlertCircle size={17} /><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss"><XCircle size={16} /></button></div>}

        <section className="workspace-grid">
          <section className="panel workbench-panel" id="workbench">
            <div className="panel-heading">
              <div><h2>Rule workbench</h2><p>Paste a Sigma-style YAML rule or choose a saved rule</p></div>
              <span className="local-badge"><span /> LOCAL</span>
            </div>
            <div className="editor-window">
              <div className="editor-toolbar"><div className="window-dots"><i /><i /><i /></div><span>detect_suspicious_whoami.yml</span><button onClick={() => setRule(SAMPLE_RULE)} title="Restore example rule"><RefreshCw size={13} /></button></div>
              <textarea className="code-editor" spellCheck="false" aria-label="Sigma YAML rule editor" value={rule} onChange={(event) => setRule(event.target.value)} />
            </div>
            <div className="workbench-actions">
              <button className="primary-button" onClick={validateRule} disabled={!!busy || !rule.trim()}>{busy === "validate" ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}Validate rule</button>
              <button className="secondary-button" onClick={testEvents} disabled={!!busy || !rule.trim()}>{busy === "test" ? <LoaderCircle className="spin" size={15} /> : <Play size={14} />}Test events</button>
              <span className="action-hint"><LockIcon /> Validation is deterministic and local</span>
            </div>
          </section>

          <section className="panel validation-panel">
            <div className="panel-heading"><div><h2>Validation results</h2><p>Live feedback from the rule engine</p></div></div>
            {validation ? (
              <>
                <div className={`validation-status ${validation.valid ? "valid" : "invalid"}`}>
                  {validation.valid ? <CheckCircle2 size={19} /> : <XCircle size={19} />}
                  <div><strong>{validation.valid ? "Rule structure valid" : "Rule needs attention"}</strong><span>{validation.title || "Untitled rule"}{validation.rule_id ? ` · ${validation.rule_id}` : ""}</span></div>
                </div>
                <div className="diagnostics-title">DIAGNOSTICS <span>{diagnostics.length}</span></div>
                <div className="diagnostic-list">
                  {diagnostics.length ? diagnostics.map((item, index) => <Diagnostic key={`${item.code}-${index}`} item={item} />) : <div className="diagnostic-item"><CheckCircle2 size={14} /><span>No validation issues reported.</span></div>}
                </div>
              </>
            ) : (
              <div className="empty-state"><div className="empty-icon"><FileCode2 size={21} /></div><strong>Ready to validate</strong><span>Run validation to see structural checks and diagnostics here.</span></div>
            )}
            <div className="ai-divider" />
            <div className="ai-review-block" id="ai-review">
              <div className="ai-title"><Sparkles size={17} /><strong>Optional AI review</strong></div>
              <p>Explain intent, limitations and likely blind spots.</p>
              <div className="ai-action-row"><button className="secondary-button ai-button" onClick={explainRule} disabled={!!busy || !rule.trim()}>{busy === "explain" ? <LoaderCircle size={14} className="spin" /> : <MessageSquareText size={14} />}Ask AI to explain</button><span><KeyRound size={12} /> Requires API key</span></div>
              {aiResult && <div className="ai-result">{aiResult}</div>}
            </div>
          </section>
        </section>

        <section className="panel events-panel" id="event-results">
          <div className="events-heading">
            <div><h2>Event test results</h2><p>Supply JSON events and evaluate each against the rule condition</p></div>
            <span className="event-count">{testResult ? `${testResult.total_events} EVENTS` : "AWAITING TEST"}</span>
          </div>
          <div className="events-input">
            <div className="events-input-head"><TerminalSquare size={14} /><span>sample_events.json</span><span className="json-label">JSON</span></div>
            <textarea spellCheck="false" aria-label="JSON event input" value={eventsText} onChange={(event) => setEventsText(event.target.value)} />
          </div>
          {testResult ? (
            <>
              <div className="result-summary"><span>{testResult.matched_count} matched</span><span>{testResult.total_events - testResult.matched_count} not matched / unevaluated</span><span>{testResult.supported ? "All events evaluated" : "Some events not evaluated"}</span></div>
              <div className="results-table-wrap">
                <table className="results-table"><thead><tr><th>EVENT</th><th>IMAGE</th><th>RESULT</th><th>REASON</th></tr></thead>
                  <tbody>{resultRows.map((row) => {
                    const image = (() => { try { const list = JSON.parse(eventsText); return list[row.index]?.Image || list[row.index]?.image || "—"; } catch { return "—"; } })();
                    return <tr key={row.index}><td>{String(row.index + 1).padStart(2, "0")}</td><td className="mono-cell">{image}</td><td><ResultPill matched={row.matched} /></td><td>{row.reason}</td></tr>;
                  })}</tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="events-empty"><span>01</span><div><strong>No test run yet</strong><small>Use “Test events” above to see per-event match results and reasons.</small></div><Code2 size={18} /></div>
          )}
          <div className="panel-footnote">The engine evaluates only its documented Sigma-style subset. Unsupported syntax is reported as not evaluated.</div>
        </section>

        <footer className="footer"><span>RuleSentry AI <span className="footer-separator">·</span> Detection Workbench</span><span>Deterministic core <span className="footer-separator">·</span> AI is advisory</span></footer>
      </main>
    </div>
  );
}

function StatCard({ label, value, note, icon: Icon }) {
  return <div className="stat-card"><div className="stat-label">{label}</div><div className="stat-value-row"><strong>{value}</strong><span>{note}</span><Icon size={18} /></div></div>;
}
function Diagnostic({ item }) {
  const good = item.severity === "info" || item.severity === "success";
  return <div className={`diagnostic-item ${good ? "good" : item.severity}`}>{item.severity === "error" ? <XCircle size={14} /> : item.severity === "warning" ? <AlertCircle size={14} /> : <CheckCircle2 size={14} />}<span>{item.message}</span></div>;
}
function ResultPill({ matched }) {
  if (matched === true) return <span className="result-pill match">MATCH</span>;
  if (matched === false) return <span className="result-pill no-match">NO MATCH</span>;
  return <span className="result-pill skipped">NOT EVALUATED</span>;
}
function LockIcon() { return <KeyRound size={12} />; }

createRoot(document.getElementById("root")).render(<React.StrictMode><App /></React.StrictMode>);
