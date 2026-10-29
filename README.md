# NVR Project

Przenośna aplikacja do podglądu kamer na żywo oraz przeglądania i pobierania
nagrań z rejestratorów NVR. Na Linuxie cały runtime działa w Dockerze.

## Uruchomienie

```sh
docker compose up -d --build
```

Interfejs jest dostępny pod adresem `http://localhost:8000`. Na pierwszym
uruchomieniu dodaj rejestratory przez zakładkę **Ustawienia**. Lokalna baza
`data/dvrs.db` zawiera dane dostępowe i celowo nie jest wersjonowana.

## Testy

```sh
docker compose exec web python -m unittest discover -s tests -v
```

## Układ projektu

- `main.py` — API i interfejs aplikacji.
- `quii_archive.py` — transfer nagrań prywatnym protokołem NVR.
- `live_proxy.py`, `local_runtime.py` — odporny podgląd live oraz obsługa
  lokalnego runtime'u Windows; Linux używa usługi `go2rtc` z Compose.
- `templates/`, `static/` — interfejs WWW.
- `tests/` — testy automatyczne.
- `docs/archive.md` — opis pobierania i formatu nagrań.
- `tools/` — narzędzia pomocnicze; binaria Windows są lokalne i ignorowane.
- `data/` — wyłącznie stan lokalny (baza NVR, pliki tymczasowe, logi).

`docs/research/` i `docs/private/` zawierają materiał roboczy z analizy uCMS.
Są celowo ignorowane przez Git; nie są potrzebne do uruchomienia aplikacji.
