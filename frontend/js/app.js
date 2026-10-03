/**
 * AI Threat Intelligence Assistant — Frontend Logic
 *
 * Handles:
 *  - Form submission → POST /api/analyze
 *  - Loading / error / empty states
 *  - Rendering all 7 result cards
 *  - Recent lookups history (sessionStorage)
 *  - AI vs VirusTotal comparison (Card 7)
 */

// ============================================================
// Configuration
// ============================================================
// Use the same origin since FastAPI serves the frontend
const API_BASE = window.location.origin;
const ANALYZE_ENDPOINT = `${API_BASE}/api/analyze`;
const MAX_RECENT = 5;

// ============================================================
// DOM References
// ============================================================
const form           = document.getElementById("analyze-form");
const iocType        = document.getElementById("ioc-type");
const iocValue       = document.getElementById("ioc-value");
const analyzeBtn     = document.getElementById("analyze-btn");
const btnText        = document.getElementById("btn-text");
const btnSpinner     = document.getElementById("btn-spinner");

const stateEmpty     = document.getElementById("state-empty");
const stateLoading   = document.getElementById("state-loading");
const stateError     = document.getElementById("state-error");
const errorMessage   = document.getElementById("error-message");
const resultsGrid    = document.getElementById("results-grid");

const recentList     = document.getElementById("recent-list");

// ============================================================
// State Management
// ============================================================

/**
 * Switch between UI states: "empty", "loading", "error", "results".
 */
function setState(state) {
    stateEmpty.classList.add("hidden");
    stateLoading.classList.add("hidden");
    stateError.classList.add("hidden");
    resultsGrid.classList.add("hidden");

    switch (state) {
        case "empty":
            stateEmpty.classList.remove("hidden");
            break;
        case "loading":
            stateLoading.classList.remove("hidden");
            break;
        case "error":
            stateError.classList.remove("hidden");
            break;
        case "results":
            resultsGrid.classList.remove("hidden");
            break;
    }
}

/**
 * Toggle the analyze button between normal and loading states.
 */
function setButtonLoading(isLoading) {
    analyzeBtn.disabled = isLoading;
    btnText.textContent = isLoading ? "Analyzing..." : "Analyze";
    btnSpinner.classList.toggle("hidden", !isLoading);
}

// ============================================================
// Input Validation
// ============================================================

const VALIDATION_PATTERNS = {
    ip: /^(\d{1,3}\.){3}\d{1,3}$/,
    domain: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
    url: /^https?:\/\/.+/,
};

const VALIDATION_MESSAGES = {
    ip: "Enter a valid IPv4 address (e.g., 8.8.8.8)",
    domain: "Enter a valid domain name (e.g., example.com)",
    url: "Enter a valid URL starting with http:// or https://",
};

function validateInput(indicator, type) {
    if (!indicator) return "Please enter an indicator value.";
    const pattern = VALIDATION_PATTERNS[type];
    if (pattern && !pattern.test(indicator)) {
        return VALIDATION_MESSAGES[type];
    }
    return null; // Valid
}

// Update placeholder text when indicator type changes
iocType.addEventListener("change", () => {
    const placeholders = {
        ip: "e.g., 8.8.8.8",
        domain: "e.g., example.com",
        url: "e.g., https://example.com",
    };
    iocValue.placeholder = placeholders[iocType.value] || "Enter indicator";
});

// ============================================================
// Form Submission
// ============================================================

form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const indicator = iocValue.value.trim();
    const type = iocType.value;

    // Client-side validation
    const validationError = validateInput(indicator, type);
    if (validationError) {
        errorMessage.textContent = validationError;
        setState("error");
        return;
    }

    // Show loading
    setState("loading");
    setButtonLoading(true);

    try {
        const response = await fetch(ANALYZE_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ indicator, type }),
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `Server returned HTTP ${response.status}`);
        }

        const data = await response.json();

        // Render results
        renderResults(data);
        const riskLevel = (data.ai_report?.risk_assessment?.risk_level || "UNKNOWN").toUpperCase();
        addToRecent(indicator, type, riskLevel);
        setState("results");

    } catch (err) {
        // Distinguish between network errors and server errors
        if (err.name === "TypeError" && err.message === "Failed to fetch") {
            errorMessage.textContent =
                "Cannot connect to the backend server. Ensure it is running on " + API_BASE;
        } else {
            errorMessage.textContent = err.message || "An unexpected error occurred.";
        }
        setState("error");
    } finally {
        setButtonLoading(false);
    }
});


// ============================================================
// Render Results
// ============================================================

function renderResults(data) {
    const report = data.ai_report;
    const agg = data.aggregated_data;
    const verdict = data.combined_verdict;
    const riskLevel = (report.risk_assessment?.risk_level || "UNKNOWN").toUpperCase();

    // ---- Metadata Bar ----
    document.getElementById("meta-indicator").textContent = `Indicator: ${data.indicator}`;
    document.getElementById("meta-type").textContent = `Type: ${data.type.toUpperCase()}`;
    document.getElementById("meta-timestamp").textContent = `Time: ${formatTimestamp(data.timestamp)}`;

    // ---- Analysis Source Badge (Improvement #5) ----
    const sourceEl = document.getElementById("meta-source");
    if (report.analysis_source === "gemini") {
        sourceEl.textContent = "\u{1F7E2} Gemini AI";
        sourceEl.className = "meta-source-badge meta-source-badge--gemini";
    } else {
        sourceEl.textContent = "\u{1F7E1} Rule-Based Fallback";
        sourceEl.className = "meta-source-badge meta-source-badge--fallback";
    }

    // ---- Quick Statistics Row (Improvement #7) ----
    renderQuickStats(agg, verdict);

    // ---- Card 1: Threat Summary + colored border (Improvement #1) ----
    document.getElementById("summary-text").textContent = report.threat_summary;
    const summaryCard = document.getElementById("card-summary");
    summaryCard.className = `card summary--${getRiskClass(riskLevel)}`;

    // ---- Card 2: Risk Assessment ----
    renderRiskAssessment(report.risk_assessment, verdict);

    // ---- Card 3: Attack Types ----
    renderAttackTypes(report.potential_attack_types);

    // ---- Card 4: Investigation Steps (Improvement #6 — clean text) ----
    renderList("investigation-list", cleanStepPrefixes(report.investigation_steps), true);

    // ---- Card 5: Analyst Questions ----
    renderList("questions-list", report.analyst_questions, false);

    // ---- Card 6: Mitigation Recommendations ----
    renderList("mitigations-list", report.mitigation_recommendations, false);

    // ---- Card 7: AI vs VT Comparison — compact table (Improvement #3) ----
    renderComparisonTable(data.comparison);
}


// ============================================================
// Card 2: Risk Assessment
// ============================================================

function renderRiskAssessment(assessment, verdict) {
    const levelEl = document.getElementById("risk-level");
    const confidenceEl = document.getElementById("risk-confidence");
    const scoreEl = document.getElementById("risk-score");
    const justEl = document.getElementById("risk-justification");

    const level = (assessment.risk_level || "UNKNOWN").toUpperCase();
    levelEl.textContent = level;
    levelEl.className = `risk-badge risk-badge--${getRiskClass(level)}`;

    confidenceEl.textContent = assessment.confidence || "N/A";

    scoreEl.textContent = `${verdict.risk_score ?? 0} / 100`;

    justEl.textContent = assessment.justification || "";
}

function getRiskClass(level) {
    const map = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "CLEAN":    "clean",
    };
    return map[level] || "unknown";
}


// ============================================================
// Card 3: Attack Types (Tags)
// ============================================================

function renderAttackTypes(types) {
    const container = document.getElementById("attack-tags");
    const emptyNote = document.getElementById("attacks-empty");

    container.innerHTML = "";

    if (!types || types.length === 0) {
        emptyNote.classList.remove("hidden");
        return;
    }

    emptyNote.classList.add("hidden");
    types.forEach((t) => {
        const tag = document.createElement("span");
        tag.className = "tag";
        tag.textContent = t;
        container.appendChild(tag);
    });
}


// ============================================================
// Card 4/5/6: List Renderer
// ============================================================

function renderList(elementId, items, ordered) {
    const list = document.getElementById(elementId);
    list.innerHTML = "";

    if (!items || items.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No data available.";
        li.style.color = "var(--tertiary)";
        li.style.fontStyle = "italic";
        list.appendChild(li);
        return;
    }

    items.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        list.appendChild(li);
    });
}


// ============================================================
// Card 7: Compact Comparison Table (Improvement #3)
// ============================================================

function renderComparisonTable(comparison) {
    const tbody = document.getElementById("cmp-tbody");
    const summaryEl = document.getElementById("cmp-summary");

    const ai = comparison.ai_assessment || {};
    const vt = comparison.vt_assessment || {};
    const vtError = !!vt.error;

    // Build table rows
    const rows = [
        ["Risk Level", ai.risk_level || "N/A", vtError ? "N/A" : (vt.risk_level || "N/A")],
        ["Confidence", ai.confidence || "N/A", vtError ? "N/A" : `${vt.detection_rate_percent ?? 0}%`],
        ["Attack Types", `${ai.attack_types_identified ?? 0}`, "\u2014"],
        ["Malicious", "\u2014", vtError ? "N/A" : `${vt.malicious_detections ?? 0} / ${vt.total_engines ?? 0}`],
        ["Alignment", comparison.alignment || "N/A", "\u2014"],
    ];

    tbody.innerHTML = rows.map(([metric, aiVal, vtVal]) => {
        return `<tr><td>${escapeHtml(metric)}</td><td>${escapeHtml(aiVal)}</td><td>${escapeHtml(vtVal)}</td></tr>`;
    }).join("");

    // Summary below table
    const alignLabel = comparison.alignment || "N/A";
    const confidence = comparison.confidence_score ?? 0;
    const explanation = comparison.explanation || "";
    const alignClass = getAlignmentClass(alignLabel);

    summaryEl.innerHTML = `
        <p class="cmp-summary-label">Summary</p>
        <p>${escapeHtml(explanation)}</p>
        <p style="margin-top: var(--space-sm);">
            <span class="alignment-badge alignment-badge--${alignClass}">${alignLabel}</span>
            &nbsp; Confidence Score: <strong>${confidence}%</strong>
        </p>
    `;
}

function getAlignmentClass(label) {
    const map = {
        "Agree": "agree",
        "Partial": "partial",
        "Disagree": "disagree",
    };
    return map[label] || "partial";
}


// ============================================================
// Recent Lookups
// ============================================================

function addToRecent(indicator, type, riskLevel) {
    let recent = JSON.parse(sessionStorage.getItem("recentLookups") || "[]");

    // Remove duplicate if exists
    recent = recent.filter((r) => !(r.indicator === indicator && r.type === type));

    // Add to front with risk level
    recent.unshift({ indicator, type, risk: riskLevel || "UNKNOWN" });

    // Cap at MAX_RECENT
    recent = recent.slice(0, MAX_RECENT);

    sessionStorage.setItem("recentLookups", JSON.stringify(recent));
    renderRecentList();
}

function renderRecentList() {
    const recent = JSON.parse(sessionStorage.getItem("recentLookups") || "[]");
    recentList.innerHTML = "";

    recent.forEach(({ indicator, type, risk }) => {
        const li = document.createElement("li");
        const riskClass = getRiskClass((risk || "UNKNOWN").toUpperCase());
        li.innerHTML = `<span class="recent-risk recent-risk--${riskClass}">${risk || "?"}</span><span class="recent-type">${type}</span> ${escapeHtml(indicator)}`;
        li.addEventListener("click", () => {
            iocType.value = type;
            iocValue.value = indicator;
        });
        recentList.appendChild(li);
    });
}


// ============================================================
// Utilities
// ============================================================

function formatTimestamp(ts) {
    if (!ts) return "N/A";
    try {
        const d = new Date(ts);
        return d.toLocaleString();
    } catch {
        return ts;
    }
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Strip "Step N:" prefixes from investigation steps (Improvement #6).
 */
function cleanStepPrefixes(steps) {
    if (!steps) return [];
    return steps.map(s => s.replace(/^Step\s*\d+\s*[:.]\s*/i, ""));
}

/**
 * Render the quick statistics row (Improvement #7).
 */
function renderQuickStats(agg, verdict) {
    const vt = agg.virustotal || {};
    const abuse = agg.abuseipdb || {};

    const vtMal = vt.malicious ?? 0;
    const vtTotal = (vtMal + (vt.suspicious ?? 0) + (vt.harmless ?? 0) + (vt.undetected ?? 0)) || 0;
    const abuseScore = abuse.abuse_confidence_score ?? 0;
    const totalReports = abuse.total_reports ?? 0;
    const riskScore = verdict.risk_score ?? 0;

    document.getElementById("stat-vt-detections").textContent = ("error" in vt) ? "N/A" : `${vtMal}/${vtTotal}`;
    document.getElementById("stat-abuse-score").textContent = ("error" in abuse || "note" in abuse) ? "N/A" : `${abuseScore}%`;
    document.getElementById("stat-reports").textContent = ("error" in abuse || "note" in abuse) ? "N/A" : totalReports;
    document.getElementById("stat-risk-score").textContent = `${riskScore}/100`;
}


// ============================================================
// Initialize
// ============================================================
document.addEventListener("DOMContentLoaded", () => {
    setState("empty");
    renderRecentList();
});
