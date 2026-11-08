"""Jalankan layanan: `astria-api` atau `python -m astria_api`.

Berbeda dari `astria_common.app.run`, header proksi (X-Forwarded-*) dipercaya hanya dari IP Caddy
(`ASTRIA_TRUSTED_PROXY`). Satu proses saja: pembatas laju, cache, dan nonce HMAC ada di memori proses.
"""

import uvicorn

from astria_api.main import build_app
from astria_api.settings import Settings


def main() -> None:
    settings = Settings()
    uvicorn.run(
        build_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=None,
        proxy_headers=bool(settings.trusted_proxy),
        forwarded_allow_ips=settings.trusted_proxy or None,
        workers=1,
    )


if __name__ == "__main__":
    main()
