# Velio - A Prompt Sanitizer

A deterministic, minimal, and auditable preprocessing layer for removing **invisible and control-based prompt injection vectors** from user input.

<!-- TOC -->

- [Velio - A Prompt Sanitizer](#velio---a-prompt-sanitizer)
    - [Overview](#overview)
    - [Scope](#scope)
        - [What this sanitizer does](#what-this-sanitizer-does)
        - [What this sanitizer does NOT do](#what-this-sanitizer-does-not-do)
    - [Design Principles](#design-principles)
    - [Architecture](#architecture)
    - [Installation](#installation)
        - [Dependencies](#dependencies)
    - [Usage](#usage)
        - [Python (library)](#python-library)
        - [FastAPI Service](#fastapi-service)
            - [Run locally](#run-locally)
            - [Endpoints](#endpoints)
                - [POST /sanitize](#post-sanitize)
                - [POST /sanitize/debug](#post-sanitizedebug)
                - [GET /health](#get-health)
    - [Character Set Policy](#character-set-policy)
        - [Control characters (`Cc`)](#control-characters-cc)
        - [Format characters (`Cf`)](#format-characters-cf)
        - [Bidirectional characters](#bidirectional-characters)
    - [Security Model](#security-model)
        - [Trust assumptions](#trust-assumptions)
        - [Key controls](#key-controls)
            - [Input constraints](#input-constraints)
            - [Output handling](#output-handling)
            - [Runtime isolation](#runtime-isolation)
    - [Docker Deployment](#docker-deployment)
        - [Prerequisites](#prerequisites)
        - [Setup](#setup)
        - [Build and run](#build-and-run)
        - [Stop](#stop)
        - [Hardening applied](#hardening-applied)
    - [Testing](#testing)
        - [Core tests (`tests/testcore.py`)](#core-tests-teststestcorepy)
        - [API tests (`tests/testapi.py`)](#api-tests-teststestapipy)
        - [Fuzz testing (recommended, not yet implemented)](#fuzz-testing-recommended-not-yet-implemented)
    - [Observability](#observability)
        - [Logging (outside core)](#logging-outside-core)
        - [Metrics (optional)](#metrics-optional)
    - [Usage Guidelines](#usage-guidelines)
        - [Correct usage](#correct-usage)
        - [Incorrect usage](#incorrect-usage)
    - [Non-Features](#non-features)
    - [Versioning](#versioning)
    - [Future Extensions (optional)](#future-extensions-optional)

<!-- /TOC -->

---

## Overview

This project provides a **pure Python sanitizer** designed to normalize and clean input text before it is:

* sent to an LLM
* displayed to users
* processed by downstream systems

It focuses specifically on **rendering discrepancies**—cases where the text seen by a human differs from what a model actually receives.

> The core guarantee:
> **What the model sees is what a human can see.**

---

## Scope

### What this sanitizer does

* Normalizes Unicode (NFKC)
* Removes:

  * Zero-width and format characters (`Cf`)
  * Control characters (`Cc`): all of `\x00`–`\x1f` and `\x7f`, except `\t`, `\n`, `\r`
  * All bidirectional characters (full Unicode `Bidi_*` category)
* Produces:

  * sanitized text
  * structured findings (what was removed and where)

### What this sanitizer does NOT do

* Detect semantic prompt injection
* Classify inputs as safe or unsafe
* Replace higher-level security controls
* Interpret or execute user content

---

## Design Principles

**Deterministic**

* Same input always produces the same output
* No randomness or machine learning

**Minimal**

* Core uses Python standard library only
* No unnecessary dependencies

**Separated**

* Core logic is independent of API/UI layers
* Web interfaces are thin adapters

**Transparent**

* All mutations are reported via structured findings
* No silent transformations

**Output modes**

The sanitizer supports two output modes, selected by the caller:

* **`strip` (default):** Removed characters are deleted. Intended for library consumers passing text to an LLM or downstream system. The `findings` struct provides the audit trail.
* **`mark`:** Removed characters are replaced with a placeholder token (e.g., `[U+200B]`). Intended for API/UI consumers inspecting untrusted text visually. Makes removals visible in place.

**Fail-safe**

* Input is always treated as untrusted
* Output is safe for display only when properly escaped

---

## Architecture

```
[Core Sanitizer Library]
        ↑
   (imported by)
        ↑
[FastAPI Service Layer]
        ↑
   (optional UI)
```

**Core library**

Responsibilities:

* Unicode normalization (NFKC)
* Filtering of invisible/control characters
* Structured result generation

**API layer**

Responsibilities:

* HTTP interface
* Input validation
* Serialization

**UI layer**

A single-page web UI served at `GET /`. Provides a textarea for pasting untrusted text, a mark/strip mode toggle (mark is default), and a findings table showing per-category removal counts and codepoints. Removed characters are highlighted inline in mark mode. No JavaScript framework or build step — served as a static HTML file by the FastAPI layer.

---

## Installation

### Dependencies

Core library: Python standard library only.

API layer additionally requires:

```
pip install fastapi uvicorn
```

Tests additionally require:

```
pip install pytest httpx
```

---

## Usage

To manually try it, visit the UI and try sanitizing some string with zero width characters. One tool for generating such strings can be https://embracethered.com/blog/ascii-smuggler.html (external, may expire without notice).

For integration, see subsections bellow.

### Python (library)

```python
from sanitizer.core import sanitize

result = sanitize("hello\u200bworld")

print(result.text) # "helloworld"

print(result.findings) # Findings(removed_format=1, removed_control=0, removed_bidi=0, ...)

result = sanitize("hello\u200bworld", mode="mark") # Mark mode \u2014 for inspection/UI use
print(result.text) # "hello[U+200B]world"
```

---

### FastAPI Service

#### Run locally

```
python -m uvicorn api.app:app --host 0.0.0.0 --port 8000
```

Interactive API docs are available at `http://localhost:8000/docs`.

> Note: JSON request bodies must use `\uXXXX` escape notation for Unicode codepoints — `\xNN` is not valid JSON syntax.

---

#### Endpoints

##### POST /sanitize

Sanitizes input text. Accepts an optional `mode` field (`"strip"` or `"mark"`, default `"strip"`).

**Request**

```json
{
  "text": "hello​world",
  "mode": "strip"
}
```

**Response**

```json
{
  "text": "helloworld",
  "findings": {
    "removed_control": 0,
    "removed_format": 1,
    "removed_bidi": 0,
    "total": 1,
    "codepoints": [8203]
  }
}
```

Input is rejected with HTTP 422 if it exceeds 50 KB or if `mode` is not `"strip"` or `"mark"`.

##### POST /sanitize/debug

Same as `/sanitize` but always responds in `mark` mode regardless of the request field. Intended for human inspection of untrusted text.

##### GET /health

Returns `{"status": "ok"}`. Use for liveness checks.

---

## Character Set Policy

### Control characters (`Cc`)

Allowed: `\t` (0x09), `\n` (0x0a), `\r` (0x0d).

Removed: all other codepoints in `\x00`–`\x1f` and `\x7f`, including `\x1b` (ESC — ANSI escape sequence injection vector).

### Format characters (`Cf`)

All Unicode `Cf` category codepoints are removed, including zero-width spaces, joiners, and soft hyphens.

### Bidirectional characters

All Unicode bidi characters are removed (full removal, not limited to override/isolation subsets).

**Known limitation:** This may affect correct visual rendering of Arabic, Hebrew, and other RTL-script text in UI contexts. The sanitized output is safe for LLM input but is not a faithful visual reproduction of RTL text. Callers building multilingual pipelines should be aware of this tradeoff.

---

## Security Model

### Trust assumptions

* All input is untrusted
* Output must be safely rendered (escaped) in any UI

---

### Key controls

#### Input constraints

* Maximum input size: 50 KB (enforced by the API layer; validated on the UTF-8 encoded byte length)
* Non-string input rejected with HTTP 422

#### Output handling

* Always render as plain text
* Never inject into HTML without escaping

#### Runtime isolation

* No secrets in environment
* Prefer no outbound network access
* Run as non-root user

---

## Docker Deployment

### Prerequisites

* Docker and Docker Compose installed on the host

### Setup

```bash
cp .env.example .env
```

Edit `.env` to set the host port if the default (8000) conflicts with anything on the host:

```
HOST_PORT=<another-port>
```

### Build and run

```bash
docker compose up --build -d
```

The service will be available at `http://<host>:${HOST_PORT}/`. The `--build` flag is only needed on first run or after code changes; subsequent starts can use `docker compose up -d`.

### Stop

```bash
docker compose down
```

### Hardening applied

The container runs with the following restrictions out of the box:

* Non-root user (`velio`)
* Read-only root filesystem (`read_only: true`)
* No Linux capabilities (`cap_drop: ALL`)
* Restarts automatically on host reboot (`restart: unless-stopped`)

---
Additional recommendations for production

* Restrict the exposed port to internal network interfaces only (configure at the firewall or reverse proxy level)
* Apply CPU and memory limits via `deploy.resources` in `compose.yaml` if resource contention is a concern

---

## Testing

Run the full test suite from the project root:

```
python -m pytest
```

### Core tests (`tests/test_core.py`)

47 tests covering:

* NFKC normalization
* Control character removal (full C0 range, DEL, ESC)
* Format character removal (`Cf` category)
* All 11 bidi formatting classes, including LRM/RLM by codepoint
* Both `strip` and `mark` modes
* Findings accuracy (per-category counts, codepoint list, total)
* Edge cases (empty string, clean ASCII, clean Unicode, type error, determinism)

### API tests (`tests/test_api.py`)

14 tests covering:

* All three endpoints (`/health`, `/sanitize`, `/sanitize/debug`)
* Both output modes
* Input validation (missing field, invalid mode, oversized input, boundary)
* Debug endpoint always forces mark mode

### Fuzz testing (recommended, not yet implemented)

* Random Unicode inputs
* Ensure no crashes and stable output

---

## Observability

### Logging (outside core)

* Count of removed characters
* Suspicious inputs

### Metrics (optional)

* Frequency of invisible characters
* Input size distribution

---

## Usage Guidelines

### Correct usage

```
User Input → Sanitizer → (optional detectors) → LLM
```

### Incorrect usage

```
User Input → Sanitizer → Trust completely → LLM
```

---

## Non-Features

* No machine learning or heuristic detection
* No safe/unsafe classification
* No external content fetching
* No automatic policy enforcement

---

## Versioning

This project follows semantic versioning:

* PATCH: bug fixes
* MINOR: backward-compatible behavior changes
* MAJOR: breaking changes

---

## Future Extensions (optional)

* HTML hidden-text stripping (for RAG pipelines)
* “Reveal invisibles” visualization mode
* Configurable strictness levels
* Integration with detection systems
* Opt-in detection of visually-blank non-space codepoints (e.g., U+2800 BRAILLE PATTERN BLANK, category `So`) used to pad text or obscure token counts — this is a heuristic/semantic attack rather than an invisible-character injection, so it requires a curated list and does not fit the core's property-based rules
