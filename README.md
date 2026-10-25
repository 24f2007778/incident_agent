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

Planner requests start with a configurable `LLM_MAX_PLANNER_REQUEST_BYTES` budget (default 64 KiB) to balance transcript context against provider quotas. Transcripts are sent in full when they fit; larger transcripts are compacted to as many distinct evidence records as fit, ranked against incident details, allowed root causes, and tool descriptions. The compacted prompt includes those exact IDs in `incident.availableEvidenceIds` and directs the model to cite at least two distinct IDs. Required metadata (including the complete tool catalog and schemas) is never dropped: if it alone exceeds the configured budget, the request uses a metadata-sized floor plus transcript allowance and logs sizes. If the provider returns HTTP 413, the request is retried with a smaller transcript budget, down to 1 KiB. Planner requests are serialized through one in-process slot. For HTTP 429, the app logs safe rate-limit headers and retries once only when `Retry-After` is at most two seconds (or after one second when no such header is supplied). Each run makes one planner request, represented by exactly one `chat incident-plan` span; malformed model output fails validation rather than making an untraced correction call.

The response includes the current OTLP trace, action and receipt logs, and (while waiting) the pending dispatches and approvals. Receipt processing records outcome HTTP/error status and receipt identifiers on the matching CLIENT span. Accepted outcomes are returned in `toolResults` with their action, call, attempt, phase, tool, status, and `resultClass`; an outcome's `result` is preserved when supplied. Tool CLIENT spans carry the matching call ID, and the trace's `incident.join` links the executed tools, including effects added after diagnostics. A diagnostic failure suppresses the effect, and retries retain the logical tool span as parent. Destructive-effect approval is not exposed until all diagnostics succeed.

Receipts are applied in an immediate SQLite transaction with full synchronous commits. Duplicate receipt IDs are idempotent, concurrent receipt updates are serialized, and partial receipts leave unreported dispatches pending and visible. Configure `DATABASE_PATH` to a persistent mounted volume in production; SQLite settings cannot preserve data on an ephemeral filesystem across redeploys. Dispatch and approval logs include correlation IDs and tool names only, not arguments, evidence text, or results.
