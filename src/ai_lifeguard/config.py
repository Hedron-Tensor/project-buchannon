import json
from pathlib import Path

_DEFAULTS_DIR = Path(__file__).parent / "defaults"

_cache = {}


def _load_default(name):
    if name not in _cache:
        _cache[name] = json.loads((_DEFAULTS_DIR / name).read_text())
    return _cache[name]


def blocked_commands():
    return _load_default("blocked_commands.json")


def sensitive_paths():
    return _load_default("sensitive_paths.json")


def injection_patterns():
    return _load_default("injection_patterns.json")


def load_config(path):
    path = Path(path)

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise ImportError("Install pyyaml to use YAML configs: pip install pyyaml")
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    elif path.suffix == ".json":
        with open(path) as f:
            raw = json.load(f)
    else:
        raise ValueError(f"Unsupported config format: {path.suffix}")

    return raw.get("ai_lifeguard", raw)
