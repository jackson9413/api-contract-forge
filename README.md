# API Contract Forge

A local-first workbench for designing and reviewing API contracts.

Paste a written contract brief (or an OpenAPI 3 JSON document) and get back:
a six-axis readiness scorecard, ranked findings with evidence and a concrete
fix for each one, a prioritised fix plan, example payloads and a curl command
per operation, and a starter OpenAPI 3 file you can keep building from.

It runs entirely on your machine. No API keys, no outbound network calls, no
telemetry. The analysis engine is plain Python standard library.

## Why it matters

Most API breakage is not caused by clever code, it is caused by contracts that
were never reviewed: no error contract, no pagination, no idempotency key on a
create, a secret in a response body, a page size with no ceiling, a webhook
nobody signs. These are cheap to fix before a client writes a line of code and
expensive to fix afterwards. API Contract Forge turns a contract draft into a
short, concrete list of things to change before you publish it.

## Domain

Developer tools / API design and integration contracts. This slot was chosen
deliberately: it is not a portfolio, wealth, stock, crypto or job-tracker
clone, and it does not overlap with the SQL coach, the regex workbench, the
CSV profiler, the shell script reviewer or the capacity planner.

## Features

- Two input modes: a free-form written brief, or an OpenAPI 3 JSON document.
- 50 contract rules across six axes:
  - naming and consistency
  - error design
  - idempotency and retries
  - pagination and listing
  - security and access
  - versioning and compatibility
- Four API profiles that re-weight the scorecard:
  general REST, public/partner, internal service, webhook/event.
- Structural score caps: a contract with no authentication cannot score well
  on security no matter how tidy the rest is.
- Every finding carries the evidence that triggered it and a specific fix.
- Example request and response payloads plus a curl command per operation.
- Starter OpenAPI 3 export generated from the parsed contract.
- Markdown, JSON and OpenAPI YAML exports.
- SQLite session log with a one-to-five star self-rating and notes.

## Quick start

    cd ~/Desktop/OpenClaw_Daily/2026-11-01/api-contract-forge
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python3 app.py

Then open http://127.0.0.1:8765

Flask is the only dependency. You can also run it with any WSGI server:

    gunicorn app:app --bind 127.0.0.1:8765

## Running the tests

    python3 -m unittest discover -s tests -v

## REST API

    GET  /api/health
    GET  /api/profiles
    GET  /api/samples
    GET  /api/sample/<sample_id>
    POST /api/analyze          {"input": "...", "mode": "auto|brief|openapi", "profile": "rest"}
    GET  /api/sessions
    GET  /api/sessions/<id>
    PATCH /api/sessions/<id>   {"notes": "...", "rating": 1-5}
    GET  /api/export/<id>?fmt=md|json|yaml

## How a brief is parsed

The parser is deliberately forgiving, because real contracts are written by
people, not by generators:

- Lines like "POST /v1/orders" start a new operation.
- "Body fields:", "Query params:", "Path params:" and "Headers:" sections are
  parsed for field names, types, required flags, defaults and maximums.
- "Returns 200 with ..." starts a response section; JSON-ish objects inside
  braces are read for response field names.
- Status codes anywhere in an operation block are collected, so "404 when the
  order does not exist" counts as a documented 404.
- Authentication, scopes, idempotency, rate limits, pagination, deprecation
  and webhook language are detected across the whole document.

Prose verbs are not mistaken for endpoints: "Delete a payment." does not
become a DELETE operation, because an operation path must start with a slash.

## Example

A contract that scores well looks like this:

    POST /v1/orders
    Creates an order. Body fields: customer_id (string, required), items (array, required).
    Returns 201 with the created order and a Location header. The Idempotency-Key
    header is supported so retries are safe.

And a contract that does not:

    POST /payments
    Create a payment. Body: amount, currency, card_number, api_key. Returns 200.

The second one scores 51 out of 100 and comes back with eight high-severity
findings: no authentication, no documented error responses, no pagination, no
idempotency key, no versioning, and a card number in the response body.

## Project layout

    app.py                 Flask routes, SQLite session log, exports
    engine.py              parsers, 50 rules, scoring, OpenAPI builder, exporters
    samples.py             four built-in sample contracts
    templates/index.html   single page UI
    static/styles.css      dark theme
    static/app.js          front end, no framework
    tests/test_engine.py   smoke tests for the engine and the HTTP API

## Built-in samples

- Orders API (written brief): a well-run partner API, scores 99.5.
- Payments API (rough brief): a typical first draft, scores 51.
- Payments API (OpenAPI 3 JSON): a structured document with the usual gaps.
- Partner Events API (webhook delivery): no signature scheme, no delivery id.

## License

MIT.
