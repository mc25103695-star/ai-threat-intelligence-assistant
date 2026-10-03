# 🛡️ AI-Powered Threat Intelligence Assistant

An AI-powered cybersecurity tool that analyzes **IP addresses**, **domains**, and **URLs** for potential threats. It collects intelligence from multiple threat feeds, uses **Google Gemini AI** for analysis, and produces structured, analyst-friendly threat reports — all from a professional SOC-grade dashboard.

---

## 🎯 Features

- **Multi-Source Intelligence** — Aggregates data concurrently from VirusTotal and AbuseIPDB
- **AI-Powered Analysis** — Google Gemini generates structured threat assessments with JSON schema validation
- **Rule-Based Fallback** — Deterministic analysis engine activates when AI is unavailable (429/quota)
- **Analyst-Friendly Reports** — Threat summary, risk level, attack types, investigation steps, and mitigation recommendations
- **AI vs VirusTotal Comparison** — Backend service that validates AI findings against real threat detection data
- **Quick Statistics** — At-a-glance KPIs: VT detections, abuse score, historical reports, risk score
- **Professional Dashboard** — Enterprise SOC-grade interface (Splunk/Falcon aesthetic)
- **Color-Coded Severity** — Threat summary card borders and badges reflect risk level
- **Session History** — Recent lookups with risk badges persist during browser session

---

## 🖥️ Dashboard Preview

The dashboard is designed to look like a real internal cybersecurity tool:

- **Left panel** — Indicator input form, recent lookups with risk badges, data source status
- **Right panel** — Quick stats row, threat summary with severity border, risk assessment, attack types, investigation steps, analyst questions, mitigation recommendations, and a compact AI vs VT comparison table

---

## 🏗️ Architecture

```
                          ┌─────────────────────────┐
                          │     Frontend Dashboard   │
                          │    (HTML / CSS / JS)     │
                          └──────────┬──────────────┘
                                     │ POST /api/analyze
                          ┌──────────▼──────────────┐
                          │     FastAPI Backend      │
                          │   (Validation + CORS)    │
                          └──────────┬──────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
          ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
          │  VirusTotal  │ │  AbuseIPDB   │ │   Gemini AI  │
          │  API Client  │ │  API Client  │ │  (or Fallback)│
          └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
                 │                │                 │
                 └────────┬───────┘                 │
                          ▼                         │
                  ┌───────────────┐                 │
                  │  Aggregator   │─── compact ────▶│
                  │  (Risk Score) │    summary       │
                  └───────────────┘                 │
                          │                         │
                          ▼                         ▼
                  ┌───────────────┐        ┌───────────────┐
                  │  Comparison   │◀───────│  AI Report    │
                  │   Service     │        │  (Structured) │
                  └───────┬───────┘        └───────────────┘
                          ▼
                  ┌───────────────┐
                  │   Response    │
                  │   (JSON)      │
                  └───────────────┘
```

---

## 📁 Project Structure

```
ai-threat-intelligence-assistant/
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI entry point + static file serving
│   │   ├── config.py                  # Environment config with startup validation
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── schemas.py             # Pydantic request/response models
│   │   │
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   └── threat_routes.py       # POST /api/analyze + dev/test routes
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── virustotal_service.py  # VirusTotal API client
│   │   │   ├── abuseipdb_service.py   # AbuseIPDB API client
│   │   │   ├── aggregator.py          # Multi-source data aggregation + risk scoring
│   │   │   ├── gemini_service.py      # Gemini AI analysis + fallback engine
│   │   │   └── comparison_service.py  # AI vs VirusTotal alignment comparison
│   │   │
│   │   └── utils/
│   │       └── __init__.py
│   │
│   ├── requirements.txt               # Python dependencies
│   ├── .env                           # API keys (never committed)
│   └── .env.example                   # Template for .env
│
├── frontend/
│   ├── index.html                     # Dashboard HTML
│   ├── css/
│   │   └── style.css                  # Enterprise SOC design system
│   ├── js/
│   │   └── app.js                     # Frontend logic + API integration
│   └── assets/
│       └── .gitkeep
│
├── .gitignore
└── README.md
```

---

## 🛠️ Tech Stack

| Layer              | Technology                 |
| ------------------ | -------------------------- |
| Backend Framework  | FastAPI (Python 3.10+)     |
| AI Engine          | Google Gemini 2.5 Flash    |
| Threat Intel       | VirusTotal, AbuseIPDB      |
| Frontend           | HTML5, CSS3, Vanilla JS    |
| HTTP Client        | httpx (async-capable)      |
| Environment Mgmt   | python-dotenv             |
| Data Validation    | Pydantic v2                |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Git
- API keys (free tier) for Gemini, VirusTotal, and AbuseIPDB

### 1. Clone the Repository

```bash
git clone https://github.com/mc25103695-star/ai-threat-intelligence-assistant.git
cd ai-threat-intelligence-assistant
```

### 2. Create Virtual Environment

```bash
cd backend
python -m venv .venv
```

**Activate it:**

| OS            | Command                        |
| ------------- | ------------------------------ |
| Windows       | `.venv\Scripts\activate`       |
| macOS / Linux | `source .venv/bin/activate`    |

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

```bash
# Copy the template
cp .env.example .env    # (Windows: copy .env.example .env)

# Edit .env and add your API keys
```

| Variable           | Where to get it                                   |
| ------------------ | ------------------------------------------------- |
| `GEMINI_API_KEY`   | https://aistudio.google.com/apikey                |
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us           |
| `ABUSEIPDB_API_KEY`  | https://www.abuseipdb.com/account/api            |

### 5. Run the Server

```bash
uvicorn app.main:app --reload --port 8000
```

### 6. Open the Dashboard

| URL                              | Description              |
| -------------------------------- | ------------------------ |
| http://localhost:8000            | Dashboard UI             |
| http://localhost:8000/docs       | Swagger API Docs         |
| http://localhost:8000/health     | Health Check             |
| http://localhost:8000/config/status | API Key Status (safe)  |

---

## 📡 API Endpoints

### Production

| Method | Endpoint         | Description                                |
| ------ | ---------------- | ------------------------------------------ |
| POST   | `/api/analyze`   | Full threat analysis pipeline              |

**Request Body:**
```json
{
  "indicator": "8.8.8.8",
  "type": "ip"
}
```

**Supported types:** `ip`, `domain`, `url`

### Health / Status

| Method | Endpoint          | Description                |
| ------ | ----------------- | -------------------------- |
| GET    | `/`               | Dashboard UI               |
| GET    | `/health`         | Health check               |
| GET    | `/config/status`  | API key config status      |
| GET    | `/docs`           | Swagger UI                 |

### Dev / Test

| Method | Endpoint                 | Description                    |
| ------ | ------------------------ | ------------------------------ |
| GET    | `/api/test/virustotal`   | Test VirusTotal integration    |
| GET    | `/api/test/abuseipdb`    | Test AbuseIPDB integration     |

---

## 🔑 Environment Variables

| Variable             | Description                    | Required | Default           |
| -------------------- | ------------------------------ | -------- | ----------------- |
| `GEMINI_API_KEY`     | Google Gemini API key          | ✅       | —                 |
| `GEMINI_MODEL`       | Gemini model to use            | ❌       | `gemini-2.5-flash`|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key             | ✅       | —                 |
| `ABUSEIPDB_API_KEY`  | AbuseIPDB API key              | ✅       | —                 |

---

## 🧠 How It Works

### Analysis Pipeline

1. **Input Validation** — Pydantic validates indicator type and format
2. **Intelligence Collection** — VirusTotal and AbuseIPDB are queried concurrently
3. **Risk Aggregation** — Scores are normalized and a combined risk verdict is computed
4. **AI Analysis** — Compact data summary is sent to Gemini with a structured JSON prompt
5. **Fallback Engine** — If Gemini returns 429/error, a deterministic rule-based analysis generates the report
6. **AI vs VT Comparison** — Backend compares AI risk assessment against VT detection data
7. **Response** — Structured JSON with the full report, raw data, comparison, and verdict

### Resilience Design

- **Gemini quota exceeded (429)?** → Automatic fallback to rule-based analysis
- **VirusTotal unavailable?** → Report continues with AbuseIPDB data only
- **AbuseIPDB unavailable?** → Report continues with VirusTotal data only
- **Both APIs down?** → Graceful error with clear message
- **Invalid Gemini JSON?** → Schema validation catches it → fallback activates

---

## 📜 License

This project is built for educational and internship purposes.

---

## 🙏 Acknowledgments

- [Google Gemini](https://ai.google.dev/) — AI analysis engine
- [VirusTotal](https://www.virustotal.com/) — Malware and threat intelligence
- [AbuseIPDB](https://www.abuseipdb.com/) — IP abuse reporting database
- [FastAPI](https://fastapi.tiangolo.com/) — Modern Python web framework
