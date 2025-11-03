# CVSS Calculator from String — Flask API + Frontend

A minimal web app to compute the CVSS Base Score from a vector string.

- CVSS v3.1: implemented locally using the official FIRST formulas and weights.
- CVSS v4.0: provided via the `cvss` Python package (which includes the official lookup).

The UI is in Italian; API responses are JSON and language-agnostic.

## Quick Start

Requirements:
- Python 3.8+

Setup and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000/ in your browser.

## Features
- Simple HTML form to input a CVSS vector (v3.1 or v4.0).
- REST endpoint to compute the Base Score from the provided vector.
- Clear JSON errors for invalid/missing input or missing v4.0 dependency.

## API

- GET `/health`
  - Returns `{ "status": "ok" }`.

- GET or POST `/calculate`
  - Input
    - GET: `?vector=CVSS:3.1/AV:N/AC:L/...`
    - POST JSON: `{ "vector": "CVSS:3.1/AV:N/..." }`
    - POST form: `vector=CVSS:...`
  - Success Response (200)
    ```json
    {
      "vector": "CVSS:3.1/...",
      "version": "3.1",
      "score": 9.8
    }
    ```
  - Error Responses
    - 400 `invalid_input` (bad or incomplete vector)
    - 400 `missing_vector` (no vector provided)
    - 500 `runtime_error` (e.g., missing `cvss` package for v4.0)

Examples:

```bash
# v3.1
curl 'http://localhost:5000/calculate?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

# v4.0 (requires the cvss package)
curl -X POST http://localhost:5000/calculate \
  -H 'Content-Type: application/json' \
  -d '{"vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}'
```

## Frontend
- Open `http://localhost:5000/`.
- Enter a CVSS vector in the input field, or click one of the example buttons.
- Click “Calcola” to compute the base score. Errors (e.g., invalid metrics) are shown clearly.

## CVSS Versions & Metrics

- v3.1 (Base metrics required): `AV, AC, PR, UI, S, C, I, A`.
- v4.0 (Base metrics required): `AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA`.
  - Requires the `cvss` package. It’s listed in `requirements.txt`.

## Project Structure

```
app.py                 # Flask app (API + UI route)
cvssCalculator.py      # CVSS v3.1 calculator + v4.0 bridge via 'cvss'
requirements.txt       # Dependencies (Flask + optional cvss)

templates/
  index.html           # Frontend page

static/
  app.js               # Frontend logic (fetches /calculate)
  styles.css           # Minimal styling
```

## Deployment Notes
- Use a production WEGSI server (e.g., gunicorn or waitress) instead of the built-in dev server.
  - Example: `gunicorn 'app:app' --bind 0.0.0.0:5000 --workers 2`
- Disable Flask debug in production.
- Consider enabling HTTPS and putting the app behind a reverse proxy (nginx, Caddy, etc.).
- If exposing the API cross-origin, configure CORS appropriately (e.g., Flask-CORS for selected origins).
- Add rate limiting and request size limits if making the API public.
- Monitor and pin dependencies; apply security updates regularly.

## General Recommendations
- Validate vectors on the client and server; return actionable error messages.
- Prefer using official CVSS documentation from FIRST when building vectors:
  - v3.1: “CVSS v3.1 Specification”
  - v4.0: “CVSS v4.0 Specification”
- Interpret scores in context: Base Score alone does not reflect Temporal or Environmental factors.
- For CVSS v4.0, ensure the `cvss` package is installed; otherwise the API will return a `runtime_error`.
- Log errors without storing sensitive data; avoid logging full vectors in production logs if they might contain internal details.
- Include unit tests for parsing and edge cases if you extend the calculator.

## Known Limitations
- Computes Base Score only (no Temporal or Environmental metrics).
- v4.0 depends on the external `cvss` package for official lookup.
- No authentication, persistence, or rate limiting included by default.

## Development Tips
- Run the server locally with `python app.py`.
- Quick Python REPL check for v3.1:
  ```python
  import cvssCalculator as c
  c.compute_from_vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  ```
- If you modify frontend assets, simply refresh the browser; no build step required.

## Credits
- Based on FIRST’s CVSS specifications.
- CVSS v4.0 support via the [`cvss`](https://pypi.org/project/cvss/) Python package.

