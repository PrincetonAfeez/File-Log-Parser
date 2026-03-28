# settings.py
"""YAML-backed configuration for the log parser."""

# Enable postponed evaluation of annotations for modern type hinting support.
from __future__ import annotations

# Import dataclasses for creating immutable, boilerplate-free data containers.
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParserSettings:
    """
    Immutable view of parser and security options loaded from config.

    Used to drive noise filtering (ignored URL extensions) and default
    security thresholds without scattering dict lookups through the codebase.
    """

    # The internal storage for the raw dictionary loaded from the YAML file.
    _raw: dict[str, Any]

    @classmethod
    def load(cls, path: str, encoding: str = "utf-8") -> "ParserSettings":
        """Read ``path`` as YAML and return a ``ParserSettings`` instance."""
        # Local import of PyYAML to ensure it is only a dependency if the config is loaded.
        import yaml

        # Open the configuration file safely using a context manager.
        with open(path, "r", encoding=encoding) as f:
            # Parse the YAML file into a Python dictionary; default to empty dict if file is empty.
            data = yaml.safe_load(f) or {}
        
        # Return a new instance of the class, ensuring the data is wrapped in a dictionary.
        return cls(_raw=data if isinstance(data, dict) else {})

    def as_dict(self) -> dict[str, Any]:
        """Return a shallow copy of the parsed YAML root for legacy ``parser.config`` access."""
        # Provides a safe way to access the full config without allowing mutation of the original.
        return dict(self._raw)

    @property
    def security_threshold(self) -> int:
        """Maximum allowed 404 responses per IP before export/alert logic flags it."""
        # Navigate the nested YAML structure: security -> threshold.
        sec = self._raw.get("security") or {}
        # Return the value as an integer, defaulting to 50 if the key is missing.
        return int(sec.get("threshold", 50))

    @property
    def ignore_extensions(self) -> tuple[str, ...]:
        """File suffixes (e.g. ``.css``) on request paths that count as noise."""
        # Navigate the nested YAML structure: parser -> ignore_extensions.
        parser_cfg = self._raw.get("parser") or {}
        # Retrieve the list of extensions; default to an empty list if not found.
        exts = parser_cfg.get("ignore_extensions") or []
        # Convert the list to an immutable tuple of strings to prevent downstream modification.
        return tuple(ext if isinstance(ext, str) else str(ext) for ext in exts)