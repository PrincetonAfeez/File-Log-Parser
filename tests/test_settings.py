"""Tests for YAML-backed parser settings."""

from pathlib import Path

from settings import ParserSettings


def test_parser_settings_loads_threshold_and_extensions(tmp_path: Path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "security:\n  threshold: 42\n"
        "parser:\n  ignore_extensions: [\".gif\", \".woff\"]\n",
        encoding="utf-8",
    )
    s = ParserSettings.load(str(cfg))
    assert s.security_threshold == 42
    assert s.ignore_extensions == (".gif", ".woff")


def test_parser_settings_defaults_when_keys_missing(tmp_path: Path):
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("{}\n", encoding="utf-8")
    s = ParserSettings.load(str(cfg))
    assert s.security_threshold == 50
    assert s.ignore_extensions == ()


def test_as_dict_is_shallow_copy(tmp_path: Path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("parser:\n  ignore_extensions: [\".css\"]\n", encoding="utf-8")
    s = ParserSettings.load(str(cfg))
    d = s.as_dict()
    d["extra"] = 1
    assert "extra" not in s.as_dict()
