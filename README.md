# Incident Response Agent

## Files
- `incident_agent.py`: FastAPI application
- `requirements_incident.txt`: Python dependencies

## Render deployment
Build command:
```bash
pip install -r requirements_incident.txt
```

Start command:
```bash
uvicorn incident_agent:app --host 0.0.0.0 --port $PORT
```

## Environment variables
Set the variables required by the application in your hosting provider's environment settings. Keep API keys private. If using Groq, typical values are:
- `LLM_API_KEY`: your Groq API key
- `LLM_BASE_URL`: `https://api.groq.com/openai/v1`
- `LLM_MODEL`: a model available to your account
- `DATABASE_PATH`: path to a durable database file if supported by your deployment

Note: a local SQLite file on an ephemeral hosting filesystem may not survive restarts or redeploys. Verify the app against the full assignment contract before using a limited Check/Save attempt.
