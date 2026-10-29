# Archiwum NVR

Podgląd MP4 i pobieranie AVI korzystają z rzeczywistego transferu archiwum na
porcie TCP ustawionym dla rejestratora (standardowo 34567). Lista plików nadal
pochodzi z `g.rec.session` / `g.rec.msg`. Pełny `filename` jest zachowany,
sprawdzany na liście urządzenia i dopiero potem interpretowany jako metadane
żądania binarnego. Nie ma zastępczych nagrań ani archiwalnych adresów RTSP.

## Uruchomienie

Dotychczasowy Dockerfile zawiera OpenSSL i FFmpeg. Po zmianie źródeł:

```sh
docker compose up -d --build
```

Na Windows zainstaluj zależności z `requirements.txt`, zapewnij `openssl` w PATH
i wskaż FFmpeg przez PATH lub zmienną `FFMPEG_BIN` (pełna ścieżka do ffmpeg.exe).
Uruchamiaj `uvicorn main:app` z katalogu projektu, aby korzystać z jego bazy.

Podgląd Live wymaga osobno uruchomionego go2rtc. Na Windows domyślny adres
jego API to `http://127.0.0.1:1984`, a w Dockerze pozostaje
`http://go2rtc:1984`. Zmienna `GO2RTC_API` pozwala nadpisać adres. Uruchom
lokalny go2rtc przed aplikacją i ustaw jego `ffmpeg.bin` na ścieżkę do FFmpeg,
aby tryb HQ mógł przekodować HEVC do H.264. Źródłem FFmpeg jest lokalny
przekaźnik go2rtc; nie przekazujemy mu danych logowania do NVR.

## Zachowanie

- Podgląd: domyślnie pierwsze 60 s pliku, H.264, maksymalnie 1280 px szerokości,
  MP4 zgodne z przeglądarką. `ARCHIVE_PREVIEW_SECONDS` ustawia limit 1–300 s.
- AVI: cały wskazany plik lub nagrania pokrywające wskazany zakres. Obraz
  zachowuje oryginalny kodek i rozdzielczość; odtwarzacz musi obsługiwać HEVC,
  jeśli kamera zapisuje HEVC.
- Oba formaty obecnie zawierają tylko obraz, bez dźwięku.
- Początek zakresu może przesunąć się do następnej dostępnej klatki kluczowej.
  Przerwy w nagraniach nie są uzupełniane sztucznym obrazem.
- Zmienna wartość pola liczby klatek nie przerywa transferu. Średnie tempo
  obrazu AVI/MP4 jest wyliczane ze źródłowych znaczników czasu, osobno dla
  pobieranych segmentów. Kontenery mają stałe średnie FPS; przy materiale
  o zmiennym FPS odstępy między poszczególnymi klatkami są uśrednione.
- Rzeczywista zmiana kodeka wewnątrz zakresu kończy się czytelnym błędem;
  w takim przypadku wybierz krótszy zakres.
- Dwie operacje przygotowania mogą działać równolegle. Domyślny limit materiału
  to 4 GiB (`ARCHIVE_MAX_BYTES`), a pojedynczego transferu 900 s
  (`ARCHIVE_TRANSFER_TIMEOUT`).
- Pliki robocze w `data/archive-tmp` są usuwane po wysłaniu odpowiedzi lub błędzie.
  Po awaryjnym zakończeniu procesu pozostałości można usunąć po zatrzymaniu aplikacji.

## Sprawdzenie

```sh
python -m unittest discover -s tests -v
```

Transport sprawdzono na prawdziwym Server409, na dwóch kamerach i różnych
plikach. Sprawdzono również HTTP: listę archiwum, MP4, AVI z zakresu, pełny
krótki plik przechodzący przez północ, błędne parametry i usuwanie plików
roboczych. Pliki AVI/MP4 przeszły pełne dekodowanie FFmpeg.

Podgląd Live nie był zmieniany. Zgodność z pozostałymi rejestratorami wymaga
sprawdzenia na ich własnych nagraniach. Nie zapisuj haseł ani przechwyconych
pakietów do repozytorium: protokół przenosi dane logowania jawnym tekstem.


## Ustawienia pobierania na komputer użytkownika

Zakładka Ustawienia, za Nagrania, zawiera zwijaną kategorię Pobieranie nagrań.
Ustawienia są oddzielne dla każdej przeglądarki: localStorage przechowuje format,
profil jakości i opcję wyboru miejsca przy każdym zapisie, a IndexedDB przechowuje
uchwyt do zatwierdzonego przez użytkownika folderu. Pełna lokalna ścieżka ani
uchwyt nie są przesyłane do serwera.

Pierwszy wybór folderu proponuje systemową lokalizację `videos`; użytkownik musi
zatwierdzić katalog. Przeglądarka udostępnia aplikacji nazwę folderu zamiast pełnej
ścieżki. Po cofnięciu uprawnienia aplikacja prosi o dostęp ponownie lub o ponowny
wybór folderu. Tryb ręczny używa natywnego okna Zapisz jako dla każdego pliku,
przed rozpoczęciem transferu. Nie ma zastępczego zapisu do katalogu Pobrane.

Kontrolowany zapis wymaga przeglądarki z File System Access API (np. Chrome/Edge)
i bezpiecznego kontekstu: HTTPS przy dostępie zdalnym lub lokalnego localhost.
Brak tych możliwości jest wyświetlany w Ustawieniach i blokuje pobranie zamiast
wybierać inne miejsce bez wiedzy użytkownika. Samodzielne wskazanie folderu
w natywnym oknie musi wykonać użytkownik; nie ustawiamy arbitralnej ścieżki.

Format AVI/MP4 i jakość dotyczą każdego nowego pobrania, pliku i zakresu:
- oryginał: kopiowanie źródłowego H.264/HEVC, bez ponownej kompresji;
- 1080p, 720p, 480p: H.264 z limitem wysokości, bez powiększania źródła.

MP4 w jakości oryginalnej zachowuje HEVC, jeśli taki jest kodek kamery; zgodność
odtwarzacza wymaga wtedy HEVC. Profile przetwarzane używają H.264. Limit czasu
ich konwersji ustawia ARCHIVE_CONVERT_TIMEOUT (domyślnie 3600 s).

Zapis jest strumieniowy, bez buforowania całego nagrania w RAM. Niepełny transfer
lub anulowanie nie zatwierdza nadpisania istniejącego pliku. W folderze domyślnym
powtórzona nazwa otrzymuje kolejny numer. Wybrany ręcznie istniejący plik może
zostać zastąpiony tylko zgodnie z zatwierdzeniem w oknie Zapisz jako.

Testy klienta: `node --test tests/downloads.test.mjs`. Sprawdzono 8 kombinacji
AVI/MP4 i jakości na rzeczywistym nagraniu, HTTP i dekodowanie wyników oraz
zapamiętywanie ustawień po odświeżeniu strony.


## Nadzór podglądu Live

Na Windows aplikacja automatycznie uruchamia i nadzoruje lokalny go2rtc
(`tools/go2rtc.exe` lub GO2RTC_BIN). Konfiguracja robocza i log znajdują się
w data/. GO2RTC_MANAGED=0 wyłącza zarządzanie. W Dockerze działa osobny
kontener z polityką restart: unless-stopped.

WebRTC jest głównym transportem. Zapasowe MP4 powstaje przez kopiowanie H.264
z lokalnego RTSP przez FFmpeg; nie używa konsumenta HTTP MP4 go2rtc, którego
awarię potwierdzono w logach. Po przerwaniu połączenia odtwarzacz ponawia
próbę automatycznie, maksymalnie trzy razy bez udanego odtworzenia. Zmiana
kamery unieważnia callbacki starego połączenia. Po udanym odtworzeniu licznik
prób jest zerowany.
