"""OIDC login configuration for Google and Microsoft accounts."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
from urllib.parse import urljoin

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request


GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
MICROSOFT_DISCOVERY_URL = (
    "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
)


def enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def google_credentials() -> tuple[str, str]:
    """Load Google OAuth credentials from environment or a local secret file.

    Google downloads web-client credentials as a JSON file. Keeping that file
    under /app/data means it is mounted at runtime but never baked into the
    image or committed to the repository.
    """
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if client_id and client_secret:
        return client_id, client_secret

    configured_file = os.environ.get("GOOGLE_CREDENTIALS_FILE", "").strip()
    if configured_file:
        candidates = [Path(configured_file)]
    else:
        candidates = sorted(Path("/app/data").glob("client_secret_*.json"))

    if not candidates:
        return "", ""
    if len(candidates) > 1:
        raise RuntimeError(
            "Znaleziono więcej niż jeden plik poświadczeń Google. "
            "Ustaw GOOGLE_CREDENTIALS_FILE."
        )

    try:
        payload = json.loads(candidates[0].read_text(encoding="utf-8"))
        web = payload["web"]
        return str(web["client_id"]), str(web["client_secret"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("Nie można odczytać pliku poświadczeń Google.") from exc


@dataclass(frozen=True)
class AuthSettings:
    enabled: bool
    session_secret: str
    public_url: str
    cookie_secure: bool
    providers: tuple[str, ...]

    @classmethod
    def from_environment(cls):
        auth_enabled = enabled(os.environ.get("AUTH_ENABLED"))
        session_secret = os.environ.get("AUTH_SESSION_SECRET", "")
        public_url = os.environ.get("AUTH_PUBLIC_URL", "").rstrip("/")
        google_client_id, google_client_secret = google_credentials()
        providers = []
        if google_client_id and google_client_secret:
            providers.append("google")
        if os.environ.get("MICROSOFT_CLIENT_ID") and os.environ.get("MICROSOFT_CLIENT_SECRET"):
            providers.append("microsoft")
        if auth_enabled:
            if len(session_secret) < 32:
                raise RuntimeError("AUTH_SESSION_SECRET musi mieć co najmniej 32 znaki.")
            if not providers:
                raise RuntimeError("Włączone logowanie wymaga konfiguracji Google lub Microsoft.")
            if not public_url:
                raise RuntimeError("AUTH_PUBLIC_URL musi wskazywać publiczny adres aplikacji.")
        return cls(
            enabled=auth_enabled,
            session_secret=session_secret,
            public_url=public_url,
            cookie_secure=enabled(os.environ.get("AUTH_COOKIE_SECURE")),
            providers=tuple(providers),
        )


settings = AuthSettings.from_environment()
oauth = OAuth()

if "google" in settings.providers:
    google_client_id, google_client_secret = google_credentials()
    oauth.register(
        name="google",
        client_id=google_client_id,
        client_secret=google_client_secret,
        server_metadata_url=GOOGLE_DISCOVERY_URL,
        client_kwargs={"scope": "openid email profile"},
    )
if "microsoft" in settings.providers:
    oauth.register(
        name="microsoft",
        client_id=os.environ["MICROSOFT_CLIENT_ID"],
        client_secret=os.environ["MICROSOFT_CLIENT_SECRET"],
        server_metadata_url=MICROSOFT_DISCOVERY_URL,
        client_kwargs={"scope": "openid email profile"},
    )


def callback_url(request: Request, provider: str) -> str:
    path = str(request.url_for("auth_callback", provider=provider))
    if not settings.public_url:
        return path
    return urljoin(settings.public_url + "/", f"auth/{provider}/callback")


def require_authenticated(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Wymagane jest zalogowanie.")
    return user
