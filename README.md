# SafeLink Scanner

Simple URL safety checker (Flask + frontend). Heuristic-based scanner with optional Google Safe Browsing integration.

## What it does
- Basic heuristics: checks for https, suspicious keywords, redirects, raw IPs, long URLs, etc.
- Prevents basic SSRF/private-host checks (blocks localhost/private IP ranges).
- Optional: Google Safe Browsing (set `GSB_API_KEY` env var for better results).

## Quick setup (local)
1. Create virtualenv:
   ```
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Run locally:
   ```
   export FLASK_ENV=development
   python app.py
   ```
   (On Windows use `set` instead of `export`)

3. Open http://127.0.0.1:5000

## Deploy to Render (example)
1. Push this repo to GitHub.
2. On Render create a new Web Service (Python).
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`
5. Add environment variables on Render:
   - `GSB_API_KEY` = (your Google Safe Browsing API key)  **DO NOT** commit this to the repo.
6. Deploy.

## Notes & security
- **Do not** commit API keys to GitHub.
- The scanner is heuristic-based and not a replacement for professional security tools.
- Consider rate-limiting `/api/scan` and adding logging/monitoring.
