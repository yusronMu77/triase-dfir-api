"""Jalankan layanan: `astria-api` atau `python -m astria_api`."""

from astria_common.app import run

from astria_api.main import build_app
from astria_api.settings import Settings


def main() -> None:
    settings = Settings()
    run(build_app(settings), settings)


if __name__ == "__main__":
    main()
