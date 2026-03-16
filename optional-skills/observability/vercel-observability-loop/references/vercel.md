# Vercel Notes

These notes are here so the skill can stay short.

## Current Assumptions

- `vercel logs --json` is the structured runtime-log path for `v1`
- `vercel api` is used for drain CRUD operations
- The drain endpoints are under `/v1/drains`
- The receiver must be publicly reachable for Vercel to deliver drain traffic
- Drain signature verification uses HMAC-SHA1 over the raw request body and compares against `x-vercel-signature`
- For the one-shot `live-session` flow, tunnel setup is automated with `cloudflared` first and `ngrok` as fallback when available

## Practical Defaults

- Use runtime logs first for immediate signal
- Use drains only for live capture or longer windows
- Store normalized logs locally in SQLite for `v1`
- Use the repo root as the code-correlation root

## Useful CLI Commands

```bash
vercel whoami
vercel logs --json --since 30m
vercel api /v1/drains
vercel api /v1/drains -X POST --input payload.json
vercel api /v1/drains/{id} -X DELETE
```

## Suggested Sources

Reasonable first-pass source sets for a general web app:

- `serverless`
- `edge-function`
- `edge-middleware`
- `static`

Tune the sources down if the project is noisy.
