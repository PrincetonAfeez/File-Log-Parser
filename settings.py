"""YAML-backed configuration for the log parser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParserSettings:
    """
    Immutable view of parser and security options loaded from config.

    Used to drive noise filtering (ignored URL extensions) and default
    security thresholds without scattering dict lookups through the codebase.
    """

    _raw: dict[str, Any]

    @classmethod
    def load(cls, path: str, encoding: str = "utf-8") -> "ParserSettings":
        """Read ``path`` as YAML and return a ``ParserSettings`` instance."""
        import yaml

        with open(path, "r", encoding=encoding) as f:
            data = yaml.safe_load(f) or {}
        return cls(_raw=data if isinstance(data, dict) else {})

    def as_dict(self) -> dict[str, Any]:
        """Return a shallow copy of the parsed YAML root for legacy ``parser.config`` access."""
        return dict(self._raw)

    @property
    def security_threshold(self) -> int:
        """Maximum allowed 404 responses per IP before export/alert logic flags it."""
        sec = self._raw.get("security") or {}
        return int(sec.get("threshold", 50))

    @property
    def ignore_extensions(self) -> tuple[str, ...]:
        """File suffixes (e.g. ``.css``) on request paths that count as noise."""
        parser_cfg = self._raw.get("parser") or {}
        exts = parser_cfg.get("ignore_extensions") or []
        return tuple(ext if isinstance(ext, str) else str(ext) for ext in exts)
