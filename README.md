# Ticketing Support System

A simple full-stack prototype:
- Frontend: `index.html`, `style.css`, `app.js`
- Backend: FastAPI (`main.py`) exposing /chat, /ticket, and static file routes

## Quick start

1. Create and activate a Python 3.10+ environment
2. Install deps
3. Run the API server
4. Open the app

## Commands

```bash
# From the project root
python -m venv .venv
source .venv/bin/activate  # On Windows bash from Git, use: source .venv/Scripts/activate
pip install -r requirements.txt

# Run backend
python main.py

# Then open http://localhost:8000 in your browser
```

If you prefer using uvicorn directly:

```bash
uvicorn main:app --reload --port 8000
```

## Notes
- The chat UI calls `http://localhost:8000/chat`. Ensure the backend is running.
- Demo logins: john.doe/password123, it.support/password123, admin/admin123
- This is an in-memory demo for the frontend and SQLite for backend.
