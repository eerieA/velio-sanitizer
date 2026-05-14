from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator
from typing import Literal

from sanitizer.core import sanitize

_TEMPLATES = Path(__file__).parent / "templates"

MAX_INPUT_BYTES = 50_000

app = FastAPI(
    title="Velio Sanitizer",
    description="Deterministic preprocessing layer for removing invisible and control-based prompt injection vectors.",
    version="0.1.0",
)


class SanitizeRequest(BaseModel):
    text: str
    mode: Literal["strip", "mark"] = "strip"

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_INPUT_BYTES:
            raise ValueError(f"input exceeds maximum size of {MAX_INPUT_BYTES} bytes")
        return v


class FindingsResponse(BaseModel):
    removed_control: int
    removed_format: int
    removed_bidi: int
    total: int
    codepoints: list[int]


class SanitizeResponse(BaseModel):
    text: str
    findings: FindingsResponse


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((_TEMPLATES / "index.html").read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize_text(req: SanitizeRequest) -> SanitizeResponse:
    result = sanitize(req.text, mode=req.mode)
    return SanitizeResponse(
        text=result.text,
        findings=FindingsResponse(
            removed_control=result.findings.removed_control,
            removed_format=result.findings.removed_format,
            removed_bidi=result.findings.removed_bidi,
            total=result.findings.total,
            codepoints=result.findings.codepoints,
        ),
    )


@app.post("/sanitize/debug", response_model=SanitizeResponse)
def sanitize_debug(req: SanitizeRequest) -> SanitizeResponse:
    """Same as /sanitize but forces mark mode regardless of the request field."""
    result = sanitize(req.text, mode="mark")
    return SanitizeResponse(
        text=result.text,
        findings=FindingsResponse(
            removed_control=result.findings.removed_control,
            removed_format=result.findings.removed_format,
            removed_bidi=result.findings.removed_bidi,
            total=result.findings.total,
            codepoints=result.findings.codepoints,
        ),
    )
