use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::report::{Report, ReportSummary};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

pub struct DashboardState {
    pub reports_dir: PathBuf,
    pub hostname: String,
    pub start_time: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub struct DashboardServer {
    bind_addr: SocketAddr,
    state: Arc<DashboardState>,
}

impl DashboardServer {
    pub fn new(bind_addr: SocketAddr, reports_dir: PathBuf) -> Self {
        let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
        Self {
            bind_addr,
            state: Arc::new(DashboardState {
                reports_dir,
                hostname,
                start_time: Utc::now(),
            }),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let app = Router::new()
            .route("/", get(serve_dashboard))
            .route("/api/reports", get(list_reports))
            .route("/api/reports/{filename}", get(get_report))
            .route("/api/latest", get(get_latest))
            .route("/api/diff", get(get_diff))
            .route("/api/trend", get(get_trend))
            .route("/api/status", get(get_status))
            .with_state(self.state.clone());

        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        tracing::info!("Dashboard listening on http://{}", self.bind_addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read and parse a report JSON file.
fn read_report(path: &std::path::Path) -> Result<Report> {
    let data = std::fs::read_to_string(path)?;
    let report: Report = serde_json::from_str(&data)?;
    Ok(report)
}

/// List JSON report files sorted by modification time (newest first).
fn list_report_files(dir: &std::path::Path) -> Vec<std::fs::DirEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<std::fs::DirEntry> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "json")
        })
        .collect();
    files.sort_by(|a, b| {
        let ta = a.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        let tb = b.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        tb.cmp(&ta)
    });
    files
}

fn compute_grade(summary: &ReportSummary) -> &'static str {
    if summary.critical > 0 {
        return "F";
    }
    if summary.high > 2 {
        return "D";
    }
    if summary.high > 0 {
        return "C";
    }
    if summary.warning > 5 {
        return "B";
    }
    if summary.warning > 0 {
        return "B+";
    }
    "A"
}

fn compute_score(summary: &ReportSummary) -> u32 {
    let penalty = summary.critical * 25 + summary.high * 15 + summary.warning * 5;
    100u32.saturating_sub(penalty as u32)
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ReportListEntry {
    filename: String,
    generated_at: String,
    hostname: String,
    total_findings: usize,
    critical: usize,
    high: usize,
    grade: String,
}

#[derive(Serialize)]
struct StatusResponse {
    hostname: String,
    uptime_seconds: i64,
    last_scan_time: Option<String>,
    reports_count: usize,
    version: String,
}

#[derive(Deserialize)]
struct DiffQuery {
    old: String,
    new: String,
}

#[derive(Serialize)]
struct DiffResponse {
    new_findings: Vec<DiffFinding>,
    resolved_findings: Vec<DiffFinding>,
    old_file: String,
    new_file: String,
}

#[derive(Serialize)]
struct DiffFinding {
    title: String,
    severity: String,
    engine: Option<String>,
}

#[derive(Deserialize)]
struct TrendQuery {
    days: Option<u32>,
}

#[derive(Serialize)]
struct TrendPoint {
    date: String,
    total: usize,
    critical: usize,
    high: usize,
    warning: usize,
    score: u32,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn list_reports(
    State(state): State<Arc<DashboardState>>,
) -> Json<Vec<ReportListEntry>> {
    let files = list_report_files(&state.reports_dir);
    let mut entries = Vec::new();
    for f in files {
        if let Ok(report) = read_report(&f.path()) {
            entries.push(ReportListEntry {
                filename: f.file_name().to_string_lossy().to_string(),
                generated_at: report.generated_at.clone(),
                hostname: report.hostname.clone(),
                total_findings: report.summary.total_findings,
                critical: report.summary.critical,
                high: report.summary.high,
                grade: compute_grade(&report.summary).to_string(),
            });
        }
    }
    Json(entries)
}

async fn get_report(
    State(state): State<Arc<DashboardState>>,
    Path(filename): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ErrorBody>)> {
    // SECURITY: prevent directory traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: "Invalid filename".into() }),
        ));
    }
    let path = state.reports_dir.join(&filename);
    match read_report(&path) {
        Ok(report) => {
            let val = serde_json::to_value(report).unwrap_or_default();
            Ok(Json(val))
        }
        Err(_) => Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorBody { error: format!("Report not found: {filename}") }),
        )),
    }
}

async fn get_latest(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ErrorBody>)> {
    let files = list_report_files(&state.reports_dir);
    if let Some(first) = files.first() {
        match read_report(&first.path()) {
            Ok(report) => {
                let val = serde_json::to_value(report).unwrap_or_default();
                Ok(Json(val))
            }
            Err(e) => Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody { error: e.to_string() }),
            )),
        }
    } else {
        Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorBody { error: "No reports found".into() }),
        ))
    }
}

async fn get_diff(
    State(state): State<Arc<DashboardState>>,
    Query(params): Query<DiffQuery>,
) -> Result<Json<DiffResponse>, (axum::http::StatusCode, Json<ErrorBody>)> {
    // SECURITY: prevent directory traversal
    for name in [&params.old, &params.new] {
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(ErrorBody { error: "Invalid filename".into() }),
            ));
        }
    }

    let old_path = state.reports_dir.join(&params.old);
    let new_path = state.reports_dir.join(&params.new);

    let old_report = read_report(&old_path).map_err(|e| {
        (axum::http::StatusCode::NOT_FOUND, Json(ErrorBody { error: e.to_string() }))
    })?;
    let new_report = read_report(&new_path).map_err(|e| {
        (axum::http::StatusCode::NOT_FOUND, Json(ErrorBody { error: e.to_string() }))
    })?;

    let old_titles: std::collections::HashSet<String> = old_report
        .sections.iter()
        .flat_map(|s| s.findings.iter())
        .map(|f| f.title.clone())
        .collect();

    let new_titles: std::collections::HashSet<String> = new_report
        .sections.iter()
        .flat_map(|s| s.findings.iter())
        .map(|f| f.title.clone())
        .collect();

    let new_findings: Vec<DiffFinding> = new_report
        .sections.iter()
        .flat_map(|s| s.findings.iter())
        .filter(|f| !old_titles.contains(&f.title))
        .map(|f| DiffFinding {
            title: f.title.clone(),
            severity: format!("{:?}", f.severity),
            engine: f.engine.clone(),
        })
        .collect();

    let resolved_findings: Vec<DiffFinding> = old_report
        .sections.iter()
        .flat_map(|s| s.findings.iter())
        .filter(|f| !new_titles.contains(&f.title))
        .map(|f| DiffFinding {
            title: f.title.clone(),
            severity: format!("{:?}", f.severity),
            engine: f.engine.clone(),
        })
        .collect();

    Ok(Json(DiffResponse {
        new_findings,
        resolved_findings,
        old_file: params.old,
        new_file: params.new,
    }))
}

async fn get_trend(
    State(state): State<Arc<DashboardState>>,
    Query(params): Query<TrendQuery>,
) -> Json<Vec<TrendPoint>> {
    let days = params.days.unwrap_or(30);
    let cutoff = Utc::now() - chrono::Duration::days(i64::from(days));
    let files = list_report_files(&state.reports_dir);

    let mut points = Vec::new();
    for f in files {
        if let Ok(report) = read_report(&f.path()) {
            if let Ok(ts) = DateTime::parse_from_rfc3339(&report.generated_at) {
                let ts_utc: DateTime<Utc> = ts.into();
                if ts_utc >= cutoff {
                    points.push(TrendPoint {
                        date: ts_utc.format("%Y-%m-%d %H:%M").to_string(),
                        total: report.summary.total_findings,
                        critical: report.summary.critical,
                        high: report.summary.high,
                        warning: report.summary.warning,
                        score: compute_score(&report.summary),
                    });
                }
            }
        }
    }
    // Oldest first for charting
    points.reverse();
    Json(points)
}

async fn get_status(
    State(state): State<Arc<DashboardState>>,
) -> Json<StatusResponse> {
    let files = list_report_files(&state.reports_dir);
    let last_scan_time = files.first().and_then(|f| {
        read_report(&f.path())
            .ok()
            .map(|r| r.generated_at)
    });
    let uptime = Utc::now() - state.start_time;

    Json(StatusResponse {
        hostname: state.hostname.clone(),
        uptime_seconds: uptime.num_seconds(),
        last_scan_time,
        reports_count: files.len(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// ---------------------------------------------------------------------------
// Embedded HTML dashboard
// ---------------------------------------------------------------------------

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DragonKeep Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0a;--surface:#111;--surface2:#1a1a1a;--border:#222;--text:#e0e0e0;--muted:#888;--accent:#00B89F;--accent-dim:#00896e;--crit:#ff4444;--high:#ff8800;--warn:#ffcc00;--info:#4488ff;--pass:#00cc66;--mono:'Menlo','Consolas','Monaco','Courier New',monospace}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

.header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:20px;font-weight:700;display:flex;align-items:center;gap:10px}
.header h1 span.icon{font-size:24px}
.header .meta{font-size:13px;color:var(--muted);font-family:var(--mono)}

.container{max-width:1400px;margin:0 auto;padding:24px}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}
.card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:6px}
.card .value{font-size:32px;font-weight:700;font-family:var(--mono)}
.card .sub{font-size:12px;color:var(--muted);margin-top:4px}
.card.crit .value{color:var(--crit)}
.card.high .value{color:var(--high)}
.card.accent .value{color:var(--accent)}

.tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border)}
.tab{padding:10px 20px;cursor:pointer;color:var(--muted);font-size:14px;border-bottom:2px solid transparent;transition:all .2s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}

.panel{display:none}
.panel.active{display:block}

table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;padding:10px 12px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none}
th:hover{color:var(--accent)}
td{padding:10px 12px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:13px}
tr:hover{background:var(--surface2)}

.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase}
.sev.Critical{background:#ff444422;color:var(--crit)}
.sev.High{background:#ff880022;color:var(--high)}
.sev.Warning{background:#ffcc0022;color:var(--warn)}
.sev.Info{background:#4488ff22;color:var(--info)}
.sev.Pass{background:#00cc6622;color:var(--pass)}

.grade{font-size:48px;font-weight:800;font-family:var(--mono)}
.grade-A{color:var(--pass)}
.grade-B,.grade-B\+{color:var(--accent)}
.grade-C{color:var(--warn)}
.grade-D{color:var(--high)}
.grade-F{color:var(--crit)}

.chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}
.chart-wrap h3{margin-bottom:16px;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
svg.trend-chart{width:100%;height:200px}

.history-list{list-style:none}
.history-list li{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:background .15s}
.history-list li:hover{background:var(--surface2)}
.history-list .ts{font-family:var(--mono);font-size:13px;color:var(--muted)}
.history-list .badge{font-size:12px;padding:2px 8px;border-radius:4px;font-weight:600}

.diff-controls{display:flex;gap:12px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.diff-controls select{background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px 12px;font-size:13px;font-family:var(--mono)}
.diff-controls button{background:var(--accent);color:#000;border:none;border-radius:4px;padding:8px 20px;font-weight:600;cursor:pointer;font-size:13px}
.diff-controls button:hover{background:var(--accent-dim)}

.diff-section{margin-bottom:20px}
.diff-section h4{margin-bottom:8px;font-size:14px}
.diff-section.new h4{color:var(--crit)}
.diff-section.resolved h4{color:var(--pass)}

.empty{text-align:center;padding:40px;color:var(--muted);font-size:14px}
.loading{text-align:center;padding:40px;color:var(--accent);font-size:14px}
</style>
</head>
<body>

<div class="header">
  <h1><span class="icon">🏰</span> DragonKeep <span style="font-weight:400;font-size:14px;color:var(--muted)">Dashboard</span></h1>
  <div class="meta" id="header-meta">Loading...</div>
</div>

<div class="container">
  <div class="cards" id="summary-cards">
    <div class="card accent"><div class="label">Total Findings</div><div class="value" id="c-total">-</div></div>
    <div class="card crit"><div class="label">Critical</div><div class="value" id="c-crit">-</div></div>
    <div class="card high"><div class="label">High</div><div class="value" id="c-high">-</div></div>
    <div class="card"><div class="label">Security Score</div><div class="value grade" id="c-grade">-</div><div class="sub" id="c-score"></div></div>
  </div>

  <div class="tabs">
    <div class="tab active" data-tab="findings">Findings</div>
    <div class="tab" data-tab="trend">Trend</div>
    <div class="tab" data-tab="history">History</div>
    <div class="tab" data-tab="diff">Diff</div>
  </div>

  <div class="panel active" id="panel-findings">
    <table id="findings-table">
      <thead><tr>
        <th data-sort="severity">Severity</th>
        <th data-sort="engine">Engine</th>
        <th data-sort="title">Title</th>
        <th>Detail</th>
        <th>CVSS</th>
      </tr></thead>
      <tbody id="findings-body"></tbody>
    </table>
    <div class="empty" id="findings-empty" style="display:none">No findings in latest report.</div>
  </div>

  <div class="panel" id="panel-trend">
    <div class="chart-wrap">
      <h3>Findings Trend (last 30 days)</h3>
      <svg class="trend-chart" id="trend-svg" viewBox="0 0 800 200" preserveAspectRatio="none"></svg>
    </div>
  </div>

  <div class="panel" id="panel-history">
    <ul class="history-list" id="history-list"></ul>
    <div class="empty" id="history-empty" style="display:none">No reports found.</div>
  </div>

  <div class="panel" id="panel-diff">
    <div class="diff-controls">
      <label style="color:var(--muted);font-size:13px">Old:</label>
      <select id="diff-old"></select>
      <label style="color:var(--muted);font-size:13px">New:</label>
      <select id="diff-new"></select>
      <button onclick="runDiff()">Compare</button>
    </div>
    <div id="diff-results"></div>
  </div>
</div>

<script>
// State
let allFindings = [];
let sortCol = 'severity';
let sortAsc = false;
const sevOrder = {Critical:0, High:1, Warning:2, Info:3, Pass:4};

// Tabs
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-' + t.dataset.tab).classList.add('active');
  });
});

// Sort headers
document.querySelectorAll('th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
    renderFindings();
  });
});

function renderFindings() {
  const tbody = document.getElementById('findings-body');
  const empty = document.getElementById('findings-empty');
  if (!allFindings.length) { tbody.innerHTML = ''; empty.style.display = ''; return; }
  empty.style.display = 'none';

  const sorted = [...allFindings].sort((a, b) => {
    let va, vb;
    if (sortCol === 'severity') { va = sevOrder[a.severity] ?? 5; vb = sevOrder[b.severity] ?? 5; }
    else if (sortCol === 'engine') { va = (a.engine || '').toLowerCase(); vb = (b.engine || '').toLowerCase(); }
    else { va = a.title.toLowerCase(); vb = b.title.toLowerCase(); }
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  tbody.innerHTML = sorted.map(f => `<tr>
    <td><span class="sev ${f.severity}">${f.severity}</span></td>
    <td>${f.engine || '-'}</td>
    <td>${esc(f.title)}</td>
    <td style="color:var(--muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.detail || '')}</td>
    <td>${f.cvss != null ? f.cvss.toFixed(1) : '-'}</td>
  </tr>`).join('');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function gradeClass(g) { return 'grade-' + g.replace('+', '\\+'); }

// Load latest report
async function loadLatest() {
  try {
    const res = await fetch('/api/latest');
    if (!res.ok) { document.getElementById('findings-empty').style.display = ''; return; }
    const report = await res.json();
    const s = report.summary;

    document.getElementById('c-total').textContent = s.total_findings;
    document.getElementById('c-crit').textContent = s.critical;
    document.getElementById('c-high').textContent = s.high;

    const grade = computeGrade(s);
    const score = computeScore(s);
    const gradeEl = document.getElementById('c-grade');
    gradeEl.textContent = grade;
    gradeEl.className = 'value grade grade-' + grade.replace('+', '\\+');
    document.getElementById('c-score').textContent = score + '/100';

    allFindings = [];
    (report.sections || []).forEach(sec => {
      (sec.findings || []).forEach(f => allFindings.push(f));
    });
    renderFindings();
  } catch(e) {
    console.error('Failed to load latest:', e);
  }
}

function computeGrade(s) {
  if (s.critical > 0) return 'F';
  if (s.high > 2) return 'D';
  if (s.high > 0) return 'C';
  if (s.warning > 5) return 'B';
  if (s.warning > 0) return 'B+';
  return 'A';
}

function computeScore(s) {
  const penalty = s.critical * 25 + s.high * 15 + s.warning * 5;
  return Math.max(0, 100 - penalty);
}

// Load status
async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const status = await res.json();
    const meta = document.getElementById('header-meta');
    const upH = Math.floor(status.uptime_seconds / 3600);
    const upM = Math.floor((status.uptime_seconds % 3600) / 60);
    meta.textContent = `${status.hostname} · v${status.version} · up ${upH}h ${upM}m · ${status.reports_count} reports`;
  } catch(e) { console.error(e); }
}

// Load history
async function loadHistory() {
  try {
    const res = await fetch('/api/reports');
    const reports = await res.json();
    const list = document.getElementById('history-list');
    const empty = document.getElementById('history-empty');

    if (!reports.length) { empty.style.display = ''; return; }
    empty.style.display = 'none';

    list.innerHTML = reports.map(r => `<li onclick="viewReport('${esc(r.filename)}')">
      <div>
        <strong>${esc(r.filename)}</strong>
        <div class="ts">${esc(r.generated_at)}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span class="sev ${r.critical > 0 ? 'Critical' : r.high > 0 ? 'High' : 'Pass'}">${r.grade}</span>
        <span style="color:var(--muted);font-size:13px">${r.total_findings} findings</span>
      </div>
    </li>`).join('');

    // Populate diff selects
    const oldSel = document.getElementById('diff-old');
    const newSel = document.getElementById('diff-new');
    oldSel.innerHTML = reports.map(r => `<option value="${esc(r.filename)}">${esc(r.filename)}</option>`).join('');
    newSel.innerHTML = reports.map(r => `<option value="${esc(r.filename)}">${esc(r.filename)}</option>`).join('');
    if (reports.length > 1) { oldSel.selectedIndex = 1; newSel.selectedIndex = 0; }
  } catch(e) { console.error(e); }
}

async function viewReport(filename) {
  try {
    const res = await fetch('/api/reports/' + encodeURIComponent(filename));
    if (!res.ok) return;
    const report = await res.json();
    allFindings = [];
    (report.sections || []).forEach(sec => {
      (sec.findings || []).forEach(f => allFindings.push(f));
    });
    const s = report.summary;
    document.getElementById('c-total').textContent = s.total_findings;
    document.getElementById('c-crit').textContent = s.critical;
    document.getElementById('c-high').textContent = s.high;
    const grade = computeGrade(s);
    const score = computeScore(s);
    const gradeEl = document.getElementById('c-grade');
    gradeEl.textContent = grade;
    gradeEl.className = 'value grade grade-' + grade.replace('+', '\\+');
    document.getElementById('c-score').textContent = score + '/100';
    renderFindings();
    // Switch to findings tab
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
    document.querySelector('[data-tab="findings"]').classList.add('active');
    document.getElementById('panel-findings').classList.add('active');
  } catch(e) { console.error(e); }
}

// Diff
async function runDiff() {
  const oldF = document.getElementById('diff-old').value;
  const newF = document.getElementById('diff-new').value;
  const results = document.getElementById('diff-results');
  results.innerHTML = '<div class="loading">Comparing...</div>';
  try {
    const res = await fetch(`/api/diff?old=${encodeURIComponent(oldF)}&new=${encodeURIComponent(newF)}`);
    if (!res.ok) { results.innerHTML = '<div class="empty">Failed to compare reports.</div>'; return; }
    const diff = await res.json();
    let html = '';
    html += `<div class="diff-section new"><h4>⚠ New Findings (${diff.new_findings.length})</h4>`;
    if (diff.new_findings.length) {
      html += '<table><thead><tr><th>Severity</th><th>Engine</th><th>Title</th></tr></thead><tbody>';
      diff.new_findings.forEach(f => {
        html += `<tr><td><span class="sev ${f.severity}">${f.severity}</span></td><td>${esc(f.engine || '-')}</td><td>${esc(f.title)}</td></tr>`;
      });
      html += '</tbody></table>';
    } else { html += '<div class="empty">No new findings.</div>'; }
    html += '</div>';

    html += `<div class="diff-section resolved"><h4>✓ Resolved Findings (${diff.resolved_findings.length})</h4>`;
    if (diff.resolved_findings.length) {
      html += '<table><thead><tr><th>Severity</th><th>Engine</th><th>Title</th></tr></thead><tbody>';
      diff.resolved_findings.forEach(f => {
        html += `<tr><td><span class="sev ${f.severity}">${f.severity}</span></td><td>${esc(f.engine || '-')}</td><td>${esc(f.title)}</td></tr>`;
      });
      html += '</tbody></table>';
    } else { html += '<div class="empty">No resolved findings.</div>'; }
    html += '</div>';
    results.innerHTML = html;
  } catch(e) { results.innerHTML = '<div class="empty">Error: ' + esc(e.message) + '</div>'; }
}

// Trend chart (SVG)
async function loadTrend() {
  try {
    const res = await fetch('/api/trend?days=30');
    const points = await res.json();
    const svg = document.getElementById('trend-svg');
    if (!points.length) { svg.innerHTML = '<text x="400" y="100" text-anchor="middle" fill="#888" font-size="14">No trend data available</text>'; return; }

    const maxVal = Math.max(1, ...points.map(p => p.total));
    const w = 800, h = 200, pad = 30;
    const step = points.length > 1 ? (w - pad * 2) / (points.length - 1) : 0;

    let totalPath = '', critPath = '', highPath = '';
    const dots = [];
    points.forEach((p, i) => {
      const x = pad + i * step;
      const yTotal = h - pad - ((p.total / maxVal) * (h - pad * 2));
      const yCrit = h - pad - ((p.critical / maxVal) * (h - pad * 2));
      const yHigh = h - pad - ((p.high / maxVal) * (h - pad * 2));
      totalPath += (i === 0 ? 'M' : 'L') + `${x},${yTotal}`;
      critPath += (i === 0 ? 'M' : 'L') + `${x},${yCrit}`;
      highPath += (i === 0 ? 'M' : 'L') + `${x},${yHigh}`;
      dots.push({x, yTotal, date: p.date, total: p.total, score: p.score});
    });

    let svgContent = '';
    // Grid lines
    for (let i = 0; i <= 4; i++) {
      const y = pad + i * ((h - pad * 2) / 4);
      const val = Math.round(maxVal - (i * maxVal / 4));
      svgContent += `<line x1="${pad}" y1="${y}" x2="${w-pad}" y2="${y}" stroke="#222" stroke-width="1"/>`;
      svgContent += `<text x="${pad-5}" y="${y+4}" text-anchor="end" fill="#555" font-size="10" font-family="monospace">${val}</text>`;
    }
    // Lines
    svgContent += `<path d="${totalPath}" fill="none" stroke="#00B89F" stroke-width="2"/>`;
    svgContent += `<path d="${critPath}" fill="none" stroke="#ff4444" stroke-width="1.5" stroke-dasharray="4,3"/>`;
    svgContent += `<path d="${highPath}" fill="none" stroke="#ff8800" stroke-width="1.5" stroke-dasharray="4,3"/>`;
    // Dots
    dots.forEach(d => {
      svgContent += `<circle cx="${d.x}" cy="${d.yTotal}" r="3" fill="#00B89F"/>`;
    });
    // X-axis labels (show first, last, middle)
    if (dots.length > 0) {
      const show = [0, Math.floor(dots.length/2), dots.length-1];
      const unique = [...new Set(show)];
      unique.forEach(i => {
        const d = dots[i];
        svgContent += `<text x="${d.x}" y="${h-5}" text-anchor="middle" fill="#555" font-size="10" font-family="monospace">${d.date.split(' ')[0]}</text>`;
      });
    }
    // Legend
    svgContent += `<text x="${w-pad}" y="15" text-anchor="end" fill="#00B89F" font-size="11">— Total</text>`;
    svgContent += `<text x="${w-pad}" y="28" text-anchor="end" fill="#ff4444" font-size="11">- - Critical</text>`;
    svgContent += `<text x="${w-pad}" y="41" text-anchor="end" fill="#ff8800" font-size="11">- - High</text>`;

    svg.innerHTML = svgContent;
  } catch(e) { console.error(e); }
}

// Init
loadStatus();
loadLatest();
loadHistory();
loadTrend();
// Refresh every 60s
setInterval(() => { loadStatus(); loadLatest(); }, 60000);
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_server_creates() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = DashboardServer::new(addr, PathBuf::from("/nonexistent"));
        assert_eq!(server.bind_addr, addr);
        assert!(!server.state.hostname.is_empty());
    }

    #[test]
    fn grade_computation() {
        let mut s = ReportSummary::default();
        assert_eq!(compute_grade(&s), "A");

        s.warning = 1;
        assert_eq!(compute_grade(&s), "B+");

        s.warning = 6;
        assert_eq!(compute_grade(&s), "B");

        s.high = 1;
        assert_eq!(compute_grade(&s), "C");

        s.high = 3;
        assert_eq!(compute_grade(&s), "D");

        s.critical = 1;
        assert_eq!(compute_grade(&s), "F");
    }

    #[test]
    fn score_computation() {
        let mut s = ReportSummary::default();
        assert_eq!(compute_score(&s), 100);

        s.warning = 2;
        assert_eq!(compute_score(&s), 90);

        s.high = 1;
        assert_eq!(compute_score(&s), 75);

        s.critical = 4;
        assert_eq!(compute_score(&s), 0); // saturates at 0
    }

    #[test]
    fn list_report_files_missing_dir() {
        let files = list_report_files(std::path::Path::new("/nonexistent_dir_dk_test"));
        assert!(files.is_empty());
    }

    #[test]
    fn html_is_embedded() {
        assert!(DASHBOARD_HTML.contains("DragonKeep"));
        assert!(DASHBOARD_HTML.contains("#0a0a0a"));
        assert!(DASHBOARD_HTML.contains("#00B89F"));
        assert!(DASHBOARD_HTML.contains("fetch("));
    }
}
