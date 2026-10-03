# Contributing

Thank you for your interest in contributing to the AI Threat Intelligence Assistant!

## Development Setup

1. Fork and clone the repository
2. Create a virtual environment: `python -m venv .venv`
3. Activate: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (macOS/Linux)
4. Install dependencies: `pip install -r backend/requirements.txt`
5. Copy `backend/.env.example` to `backend/.env` and add your API keys
6. Run the server: `cd backend && uvicorn app.main:app --reload`

## Project Guidelines

- **No hardcoded secrets** — Always use environment variables via `.env`
- **Clean architecture** — Keep services modular (one file per external API)
- **Type safety** — Use Pydantic schemas for all API request/response models
- **Logging** — Use Python's `logging` module, not `print()`
- **Frontend** — Vanilla HTML/CSS/JS only. No frameworks, no Bootstrap, no Tailwind

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Test the full pipeline: submit an IP, domain, and URL via the dashboard
4. Ensure the server starts without errors
5. Submit a pull request with a clear description
