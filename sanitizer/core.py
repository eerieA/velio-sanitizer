import unicodedata
from dataclasses import dataclass, field
from typing import Literal

# Control characters allowed through unchanged.
_ALLOWED_CONTROL = frozenset({"\t", "\n", "\r"})

# unicodedata.bidirectional() class names that represent explicit directional
# formatting — these are the injection vectors we strip.
_BIDI_FORMATTING_CLASSES = frozenset({
    "LRE", "RLE", "PDF",        # embedding
    "LRO", "RLO",               # override
    "LRI", "RLI", "FSI", "PDI", # isolate
})

# U+200E LEFT-TO-RIGHT MARK, U+200F RIGHT-TO-LEFT MARK.
# Python's unicodedata.bidirectional() reports these as "L" and "R" (their
# resolved class), not "LRM"/"RLM", so we match them by codepoint directly.
_BIDI_MARK_CODEPOINTS = frozenset({0x200E, 0x200F})


@dataclass
class Findings:
    removed_control: int = 0
    removed_format: int = 0
    removed_bidi: int = 0
    codepoints: list[int] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.removed_control + self.removed_format + self.removed_bidi


@dataclass
class SanitizeResult:
    text: str
    findings: Findings


def sanitize(text: str, mode: Literal["strip", "mark"] = "strip") -> SanitizeResult:
    """
    Normalize and clean untrusted input text.

    Applies NFKC normalization, then removes:
      - Control characters (Cc) outside the allowed set {\\t, \\n, \\r}
      - Format characters (Cf)
      - Explicit bidi directional formatting characters

    mode="strip"  — removed characters are deleted (default, for library use)
    mode="mark"   — removed characters are replaced with [U+XXXX] tokens (for UI/inspection)
    """
    if not isinstance(text, str):
        raise TypeError(f"expected str, got {type(text).__name__}")

    normalized = unicodedata.normalize("NFKC", text)

    findings = Findings()
    parts: list[str] = []

    for ch in normalized:
        category = unicodedata.category(ch)
        bidi_class = unicodedata.bidirectional(ch)

        cp = ord(ch)
        if category == "Cc" and ch not in _ALLOWED_CONTROL:
            findings.removed_control += 1
            findings.codepoints.append(cp)
            if mode == "mark":
                parts.append(f"[U+{cp:04X}]")
        elif bidi_class in _BIDI_FORMATTING_CLASSES or cp in _BIDI_MARK_CODEPOINTS:
            findings.removed_bidi += 1
            findings.codepoints.append(cp)
            if mode == "mark":
                parts.append(f"[U+{cp:04X}]")
        elif category == "Cf":
            findings.removed_format += 1
            findings.codepoints.append(cp)
            if mode == "mark":
                parts.append(f"[U+{cp:04X}]")
        else:
            parts.append(ch)

    return SanitizeResult(text="".join(parts), findings=findings)
