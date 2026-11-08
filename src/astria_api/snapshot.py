"""Tulis ulang snapshot kontrak OpenAPI: `python -m astria_api.snapshot`. Diuji agar tidak menyimpang diam-diam."""

import json
from pathlib import Path

from astria_api.main import build_app
from astria_api.settings import Settings

SNAPSHOT = Path(__file__).resolve().parents[2] / "openapi" / "api-v1.json"


def render() -> str:
    schema = build_app(Settings(env="test")).openapi()
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> None:
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"ditulis: {SNAPSHOT}")


if __name__ == "__main__":
    main()
