---
name: vercel-obs
description: Investigate Vercel-deployed apps by collecting runtime logs or configuring a drain to a local receiver, correlating the data with the current codebase, and producing bug-focused observability reports.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [vercel, observability, logging, debugging, production]
    related_skills: [native-mcp]
---

# Vercel Obs

Use this skill when the current app is deployed to Vercel and the user wants a code-aware observability pass over recent runtime logs or a temporary drain-backed capture session.

## Prerequisites

- `vercel` CLI installed and logged in
- Repo linked to a Vercel project, or the user can provide a project id/name
- For one-shot live drain capture: `cloudflared` or `ngrok` installed locally
- Drain support is plan-dependent; if drains are unavailable, fall back to runtime-log analysis

## Helper Script

Installed path:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py
```

Read `references/vercel.md` if you need the current Vercel constraints or API assumptions.

## Workflow

### 1. Preflight

Always start with:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py preflight
```

This checks for:

- linked Vercel project metadata
- CLI availability and version
- current Vercel login state
- whether `vercel api` is available for drain operations

If the repo is not linked or the CLI is not authenticated, stop and explain the blocker.

### 2. Immediate Runtime Analysis

Use runtime logs first so the user gets signal immediately:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py collect-runtime --since 30m
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py analyze --since 30m --report-path .hermes/observability/reports/runtime-report.md
```

This path is the default fallback when drain setup is not possible.

### 3. One-Shot Live Session

For a single prompt workflow, prefer the built-in orchestration command:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py live-session \
  --minutes 10 \
  --environment production \
  --report-path .hermes/observability/reports/live-session.md
```

This command will:

- start the local drain receiver
- launch a tunnel with `cloudflared` or `ngrok`
- create a temporary Vercel drain against the linked project
- collect logs for the requested window
- delete the drain
- stop the tunnel and receiver
- analyze only the rows captured during that session
- write a report

Useful flags:

- `--project-id prj_123` if the repo is not linked
- `--scope team_slug` for team-scoped Vercel access
- `--source serverless --source edge-function` to narrow the capture
- `--tunnel cloudflared` to force a provider
- `--name-prefix hermes-incident` to change the temporary drain name prefix

If the tunnel binary is missing or the drain cannot be created, the script should still clean up the local receiver before exiting with an error.

### 4. Local Receiver for Manual Live Drain Capture

Use the manual steps below only when you need fine-grained control.

Start the receiver in the background:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py serve --port 4319 --secret YOUR_SHARED_SECRET
```

Run it through Hermes background process support so it stays alive.

The receiver writes to:

- `.hermes/observability/logs.sqlite3`
- `.hermes/observability/raw/`

### 5. Expose the Receiver

If the receiver is only listening on localhost, expose it with a tunnel before creating the drain.

Preferred manual pattern:

```bash
cloudflared tunnel --url http://127.0.0.1:4319 --no-autoupdate
```

Parse the public HTTPS URL from the tunnel output. If no tunnel is available, explain that Vercel cannot deliver drains to a private localhost endpoint.

### 6. Create or Reuse the Drain

Once you have a public URL:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py ensure-drain \
  --name hermes-observability \
  --target-url https://example.trycloudflare.com \
  --project-id prj_123 \
  --secret YOUR_SHARED_SECRET \
  --source static \
  --source serverless \
  --source edge-function
```

If the project id is omitted, the script tries `.vercel/project.json`.

For teardown:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py delete-drain --drain-id d_123
```

### 7. Analyze and Report

Generate a report after enough logs have arrived:

```bash
python ~/.hermes/skills/observability/vercel-observability-loop/scripts/vercel_observability.py analyze \
  --since 2h \
  --sample-limit 20 \
  --report-path .hermes/observability/reports/observability-report.md
```

The report should prioritize:

- bug candidates
- noisy or superfluous logs
- missing context in error logs
- concrete fix proposals tied back to likely files in the repo

## Output Expectations

When using this skill, produce:

1. A short status summary of what mode you used: runtime only or drain-backed
2. The report path
3. The highest-signal findings first
4. Concrete next steps, including drain cleanup if you created one

## Hermes Prompt Patterns

Use prompts like:

```text
/vercel-obs Run a 10 minute live observability session for this repo: start live collection, set up the tunnel, create a temporary drain, collect logs, clean everything up, analyze the captured data, and write the report to .hermes/observability/reports/live-session.md.
```

```text
/vercel-obs Run preflight first, then execute a 5 minute live session against production using only serverless and edge-function logs. Summarize the top bug candidates in chat and save the full report under .hermes/observability/reports/incident-review.md.
```

## Guardrails

- Prefer read-only investigation unless the user explicitly asks for fixes
- Redact obvious secrets and tokens in reports
- Keep time windows narrow by default
- Use sampling for high-volume logs
- If drain creation fails, surface the Vercel API error and fall back to runtime-log analysis
