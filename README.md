# Incident Response Agent

## Files
- `main.py`: FastAPI application (`main:app`)
- `requirements.txt`: Python dependencies

## Render deployment
Build command:
```bash
pip install -r requirements.txt
```

Start command:
```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

## Environment variables
Set the variables required by the application in your hosting provider's environment settings. Keep API keys private. If using Groq, typical values are:
- `LLM_API_KEY`: your Groq API key
- `LLM_BASE_URL`: `https://api.groq.com/openai/v1`
- `LLM_MODEL`: a model available to your account
- `DATABASE_PATH`: path to a durable database file if supported by your deployment

Note: a local SQLite file on an ephemeral hosting filesystem may not survive restarts or redeploys. Verify the app against the full assignment contract before using a limited Check/Save attempt.

## Debugging deployment errors

The application writes request, planner, persistence, replay, and receipt lifecycle events to the standard application log. In Render, open the service's **Logs** view and filter by `run_id`. Planner failures include a reason such as `provider_http_error`, `provider_timeout`, `provider_transport_error`, or `unexpected_planning_error`; upstream HTTP status and elapsed time are included when available.

Logs intentionally exclude request bodies, transcripts, tool arguments/results, and API keys. Do not enable HTTPX wire/debug logging in production because it may expose request headers or payloads.

Planner requests are capped at 256 KiB. Transcripts are sent in full when they fit; larger transcripts are reduced to whole evidence records ranked against incident details, allowed root causes, and tool descriptions. The planner log records request size and, when reduction occurs, original/retained transcript bytes and record counts. A provider HTTP 413 means its request-body limit was exceeded; check these sizes when diagnosing it.
