from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from tools.verification.fl3_validators import FL3ValidationError


@dataclass(frozen=True)
class RenderedTemplate:
    text: str
    unresolved_placeholders: int


def render_template(*, template_text: str, mapping: Dict[str, str]) -> RenderedTemplate:
    out = str(template_text)
    for k, v in mapping.items():
        out = out.replace("{{" + k + "}}", str(v))
    unresolved = out.count("{{")
    return RenderedTemplate(text=out, unresolved_placeholders=unresolved)


def render_template_file(*, template_path: Path, mapping: Dict[str, str]) -> str:
    text = template_path.read_text(encoding="utf-8")
    rendered = render_template(template_text=text, mapping=mapping)
    if rendered.unresolved_placeholders != 0:
        raise FL3ValidationError(f"Unresolved placeholders in template (fail-closed): {template_path.as_posix()}")
    return rendered.text

