# Running the SOC triage agent

Built at Build with Gemini Tel Aviv, 23 Sep 2026. Everything in `app/tools.py` is
synthetic — invented hosts, invented logs, no real data.

## What it demonstrates

An indirect prompt injection hidden in a web log — data the agent fetches itself,
not user input — makes the agent call `suppress_alerts` and downgrade a live
intrusion to informational. The false finding then persists into Vertex AI Memory
Bank and silences the host in later sessions.

## Requirements

- Python 3.10+
- A Google Cloud project with Vertex AI enabled, **or** a Gemini API key
- `pip install google-adk` (add `a2ui-agent-sdk` for the card rendering)

## Configure

Copy `.env` and replace the values — the ones committed point at a lab project
that no longer exists.

Against Vertex AI:

```sh
GOOGLE_GENAI_USE_VERTEXAI=TRUE
GOOGLE_CLOUD_PROJECT=<your project>
GOOGLE_CLOUD_LOCATION=us-central1
MODEL=gemini-2.5-flash
```

Then `gcloud auth application-default login`.

Against the Gemini API instead:

```sh
GOOGLE_GENAI_USE_VERTEXAI=FALSE
GOOGLE_API_KEY=<key from aistudio.google.com/apikey>
MODEL=gemini-3.1-flash-lite
```

Note the free tier allows 20 requests per day per model, and each beat costs
three or four. The model matters: the payload lands reliably on
`gemini-2.5-flash` (Vertex) and `gemini-3.1-flash-lite`, and is untested on
larger models.

## Run

```sh
python3 demo.py        # all beats
python3 demo.py 2      # one beat
python3 demo.py 2 --a2ui
```

- **Beat 1** — clean alert on `bld-runner-11`, triaged correctly
- **Beat 2** — the hijack: the agent reads the intrusion, names it, then obeys
  the log line and suppresses the host
- **Beat 4** — tool responses screened before the model sees them; the same
  alert returns critical with the indicators intact
- **Beats 5 and 6** — require Memory Bank, see below

Web UI with rendered cards:

```sh
ENABLE_A2UI=true adk web . --port 8099 \
  --memory_service_uri agentengine://<your memory bank id>
```

Port 8099 rather than 8080, which is a common local collision.

## Memory Bank (needed for beats 5 and 6)

The lab's Memory Bank instance is gone with the lab project, so **beats 5 and 6
will not run until you create your own**. Provision a Reasoning Engine in your
project, then set:

```sh
MEMORY_BANK_ID=<your reasoning engine id>
MEMORY_SERVICE_URI=agentengine://<your reasoning engine id>
```

Beat 6 is the interesting one: it serves a *clean* event list for `app-web-04`
with the injection removed, so the agent's false belief can only have come from
memory. In the original run it suppressed the host for 8760 hours — the model
escalated from the 24 hours the injection asked for, unprompted.
