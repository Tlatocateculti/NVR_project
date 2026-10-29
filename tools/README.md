# Lokalny przekaźnik na Windows

Umieść `go2rtc.exe` w tym katalogu lub ustaw `GO2RTC_BIN` na jego pełną ścieżkę.
Użyta wersja pochodzi z oficjalnego wydania:
https://github.com/AlexxIT/go2rtc/releases/tag/v1.9.15

Program uruchamia aplikacja NVR, w tle. Nie jest to usługa systemowa Windows.
Podczas pracy aplikacja nadzoruje dostępność przekaźnika i w razie zakończenia
procesu uruchamia go ponownie. `GO2RTC_MANAGED=0` wyłącza zarządzanie.

Konfiguracja robocza i prywatny log powstają w `data/`; nie dodawaj ich do Git.
FFmpeg musi być dostępny w PATH lub wskazany przez `FFMPEG_BIN`.
Docker korzysta z osobnego kontenera go2rtc i nie uruchamia pliku EXE.
