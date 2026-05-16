# Velio - Minimal Prompt Sanitizer

A deterministic, minimal, and auditable preprocessing layer for removing **invisible and control-based prompt injection vectors** from user input.

<!-- TOC -->

- [Velio - Minimal Prompt Sanitizer](#velio---minimal-prompt-sanitizer)
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
                - [GET /health](#get-health)
    - [Character Set Policy](#character-set-policy)
        - [Control characters (`Cc`)](#control-characters-cc)
        - [Format characters (`Cf`)](#format-characters-cf)
        - [Bidirectional characters](#bidirectional-characters)
    - [Security Model](#security-model)
        - [Trust assumptions](#trust-assumptions)
        - [Key controls](#key-controls)
    - [Docker Deployment](#docker-deployment)
        - [Prerequisites](#prerequisites)
        - [Setup, build and run](#setup-build-and-run)
        - [Hardening applied](#hardening-applied)
    - [CI / Supply Chain Security](#ci--supply-chain-security)
        - [Threat: GitHub Actions cache poisoning](#threat-github-actions-cache-poisoning)
        - [Mitigations in place](#mitigations-in-place)
        - [Railway deployment setup](#railway-deployment-setup)
        - [Switching providers](#switching-providers)
        - [Railway CLI supply chain note](#railway-cli-supply-chain-note)
        - [Next hardening step: hash-pinned dependencies](#next-hardening-step-hash-pinned-dependencies)
    - [Testing](#testing)
        - [Core tests](#core-tests)
        - [API tests](#api-tests)
        - [Fuzz testing (not yet implemented)](#fuzz-testing-not-yet-implemented)
    - [Observability](#observability)
        - [Logging (outside core)](#logging-outside-core)
        - [Metrics (optional)](#metrics-optional)
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

**Input constraints**

* Maximum input size: 50 KB (enforced by the API layer; validated on the UTF-8 encoded byte length)
* Non-string input rejected with HTTP 422

**Output handling**

* Always render as plain text
* Never inject into HTML without escaping

**Runtime isolation**

* No secrets in environment
* Prefer no outbound network access
* Run as non-root user

---

## Docker Deployment

### Prerequisites

* Docker and Docker Compose installed on the host

### Setup, build and run

**Setup**

```bash
cp .env.example .env
```

Edit `.env` to set the host port if the default (8000) conflicts with anything on the host:

```
HOST_PORT=<another-port>
```

**Build and run**

```bash
docker compose up --build -d
```

The service will be available at `http://<host>:${HOST_PORT}/`. The `--build` flag is only needed on first run or after code changes; subsequent starts can use `docker compose up -d`.

**Stop**

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

## CI / Supply Chain Security

### Threat: GitHub Actions cache poisoning

`actions/cache` uses a runner-internal token — not the workflow's `GITHUB_TOKEN` — to write cache entries. This means `permissions: contents: read` does **not** prevent cache writes. A fork PR can therefore poison the pip/npm/pnpm cache with a malicious payload keyed to match the hash that the release workflow will later restore. The restored payload executes with full release-workflow permissions.

This is not hypothetical. The [mini-shai-hulud campaign (May 2025)](https://www.mend.io/blog/mini-shai-hulud-is-back-172-npm-and-pypi-packages-compromised-in-latest-wave/) exploited exactly this vector against multiple open-source projects, including TanStack.

### Mitigations in place

**Two separate workflow files with different trust levels**

| Workflow | Trigger | Cache | Secrets | Deploys |
|---|---|---|---|---|
| `pr-check.yml` | `pull_request` (any fork) | None | None | No |
| `deploy.yml` | `push` to `main` | pip cache | `GITHUB_TOKEN`, deploy hook | Yes |

Fork PRs run `pr-check.yml` only. Because it has no `actions/cache` step, a fork can never write to the cache that `deploy.yml` reads. Cache is used in `deploy.yml` safely because only pushes to the `main` branch trigger it.

**All third-party actions pinned to full commit SHAs**

Tags like `actions/checkout@v4` are mutable — they can be silently moved to point at a different, compromised commit. Commit SHAs are immutable. Every action in both workflow files is pinned by SHA with the tag noted in a comment for human readability.

**Pinned dependency versions**

`requirements.txt` pins exact versions of `fastapi` and `uvicorn`. The Dockerfile installs from this file rather than running `pip install fastapi uvicorn` with no version constraint, so every build is reproducible and an upstream version bump cannot silently change what gets deployed.

### Railway deployment setup

Before the first deploy, complete these steps:

1. In Railway: Account Settings → Tokens → create a token
2. In Railway: your service → Settings → copy the Service ID
3. In GitHub: Settings → Secrets and variables → Actions → add two repository secrets:
   - Name: `RAILWAY_TOKEN` — Value: token from step 1
   - Name: `RAILWAY_SERVICE_ID` — Value: service ID from step 2
4. In Railway: set your service's image to `ghcr.io/<your-github-username>/velio-sanitizer:latest`

On every push to `main`, the workflow will run tests, build and push the Docker image to GHCR, then use the Railway CLI to trigger an immediate redeploy.

### Switching providers

The Railway-specific part is a two-step block at the end of `deploy.yml`, clearly labeled. Everything before it — test run, Docker build, GHCR push — is provider-agnostic. To switch providers, replace those two steps with whatever the new provider requires (a different CLI, a webhook `curl`, etc.).

### Railway CLI supply chain note

The Railway CLI is installed at workflow runtime via `curl | bash`. Two mitigations are in place:

- The version is pinned (`RAILWAY_VERSION=4.58.0`) so the workflow always fetches the same release artifact. GitHub marks Railway releases as immutable, meaning the artifact at a given tag cannot be changed after publishing.
- The install script is only executed in `deploy.yml`, which runs exclusively on push to `main` (our own code). Fork PRs never trigger this workflow, so the attack surface is limited to trusted commits.

### Next hardening step: hash-pinned dependencies

The current `requirements.txt` pins versions but not cryptographic hashes. `pip --require-hashes` can verify every wheel against a known hash, making it impossible for a compromised PyPI mirror to substitute a different package. Generating a fully hash-pinned lockfile requires running `pip-compile` on the target platform (`linux/amd64`) because `pydantic-core` ships platform-specific wheels with different hashes. Instructions are in the comment at the top of `requirements.txt`.

---

## Testing

Run the full test suite from the project root:

```
python -m pytest
```

### Core tests

47 tests covering:

* NFKC normalization
* Control character removal (full C0 range, DEL, ESC)
* Format character removal (`Cf` category)
* All 11 bidi formatting classes, including LRM/RLM by codepoint
* Both `strip` and `mark` modes
* Findings accuracy (per-category counts, codepoint list, total)
* Edge cases (empty string, clean ASCII, clean Unicode, type error, determinism)

### API tests

14 tests covering:

* Both endpoints (`/health`, `/sanitize`)
* Both output modes
* Input validation (missing field, invalid mode, oversized input, boundary)

### Fuzz testing (not yet implemented)

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
