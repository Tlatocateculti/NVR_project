const DEFAULTS = Object.freeze({ format: 'avi', quality: 'original', askEveryTime: false });
const STORAGE_KEY = 'nvr.downloads.v1';
const FORMATS = { avi: 'video/x-msvideo', mp4: 'video/mp4' };

export function normalizeSettings(value = {}) {
    return {
        format: Object.hasOwn(FORMATS, value?.format) ? value.format : DEFAULTS.format,
        quality: ['original', '1080p', '720p', '480p'].includes(value?.quality) ? value.quality : DEFAULTS.quality,
        askEveryTime: value?.askEveryTime === true,
    };
}

export function suggestedFilename(params, format) {
    const date = params.date || 'nagranie';
    const range = `${params.start_time || '00:00:00'}_${params.end_time || '23:59:59'}`;
    return `nvr-${params.dvr_id}-kamera-${params.channel}_${date}_${range}`
        .replace(/[\\/:*?"<>|\x00-\x1f]/g, '-').slice(0, 170) + '.' + format;
}

export async function createUniqueFile(directory, filename) {
    const dot = filename.lastIndexOf('.');
    for (let index = 0; index < 10000; index++) {
        const name = index ? `${filename.slice(0, dot)} (${index})${filename.slice(dot)}` : filename;
        try {
            await directory.getFileHandle(name);
        } catch (error) {
            if (error.name !== 'NotFoundError') throw error;
            return { handle: await directory.getFileHandle(name, { create: true }), name };
        }
    }
    throw new Error('W folderze jest zbyt wiele plików o tej samej nazwie.');
}

export async function streamToFile(response, handle, onProgress = () => {}, signal) {
    if (!response.body) throw new Error('Przeglądarka nie udostępniła danych nagrania.');
    const writer = await handle.createWritable({ keepExistingData: false });
    const reader = response.body.getReader();
    const total = Number(response.headers.get('Content-Length')) || 0;
    let received = 0;
    let committed = false;
    try {
        while (true) {
            if (signal?.aborted) throw new DOMException('Anulowano zapis.', 'AbortError');
            const { value, done } = await reader.read();
            if (done) break;
            await writer.write(value);
            received += value.byteLength;
            onProgress(received, total);
        }
        if (signal?.aborted) throw new DOMException('Anulowano zapis.', 'AbortError');
        if (!received || (total && received !== total)) throw new Error('Nagranie nie zostało pobrane w całości.');
        await writer.close();
        committed = true;
        return received;
    } finally {
        if (!committed) {
            try { await writer.abort(); } catch (_) {}
            try { await reader.cancel(); } catch (_) {}
        }
        reader.releaseLock();
    }
}

function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('nvr-user-settings', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('handles');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function directoryStorage(value, write = false) {
    const database = await openDatabase();
    try {
        return await new Promise((resolve, reject) => {
            const transaction = database.transaction('handles', write ? 'readwrite' : 'readonly');
            const store = transaction.objectStore('handles');
            const request = write ? store.put(value, 'downloads') : store.get('downloads');
            transaction.oncomplete = () => resolve(request.result);
            transaction.onerror = () => reject(transaction.error);
            transaction.onabort = () => reject(transaction.error || new Error('Nie zapisano ustawień folderu.'));
        });
    } finally {
        database.close();
    }
}

let settings = { ...DEFAULTS };
let directory = null;
let ready = false;
let activeDownload = null;
const element = id => document.getElementById(id);

function supported() {
    return window.isSecureContext && typeof window.showDirectoryPicker === 'function'
        && typeof window.showSaveFilePicker === 'function';
}

function settingsMessage(text, error = false) {
    element('download-settings-status').textContent = text;
    element('download-settings-status').classList.toggle('settings-error', error);
}

function drawSettings() {
    element('download-folder').value = directory?.name || 'Filmy / Wideo — wybierz folder przy pierwszym zapisie';
    element('download-ask').checked = settings.askEveryTime;
    element('download-format').value = settings.format;
    element('download-quality').value = settings.quality;
    element('download-format-note').textContent = settings.quality === 'original'
        ? 'Oryginał zachowuje kodek, rozdzielczość i jakość nagrania. MP4 z HEVC wymaga odtwarzacza obsługującego HEVC.'
        : 'Obraz zostanie zapisany w H.264. Rozdzielczość będzie zmniejszona do wybranego limitu; mniejszych nagrań nie powiększamy.';
    window.nvrDownloadSettings = { ...settings };
    document.querySelectorAll('[data-download-label]').forEach(button => {
        const labels = { file: '⬇ Pobierz', current: '⬇ Pobierz ten plik', range: '⬇ Pobierz wskazany przedział' };
        button.textContent = `${labels[button.dataset.downloadLabel]} (${settings.format.toUpperCase()})`;
    });
    const heading = element('download-range-heading');
    if (heading) heading.textContent = `Pobierz przedział czasowy (${settings.format.toUpperCase()})`;
}

function saveSettings() {
    const next = normalizeSettings({
        format: element('download-format').value,
        quality: element('download-quality').value,
        askEveryTime: element('download-ask').checked,
    });
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
        settings = next;
        settingsMessage('Ustawienia zapisane w tej przeglądarce.');
        drawSettings();
    } catch (_) {
        drawSettings();
        settingsMessage('Przeglądarka zablokowała zapis ustawień. Sprawdź dostęp do pamięci witryny.', true);
    }
}

async function chooseDirectory() {
    if (!supported()) throw new Error('Ta przeglądarka nie obsługuje kontrolowanego zapisu nagrań.');
    const chosen = await window.showDirectoryPicker({
        id: 'nvr-recordings', mode: 'readwrite', startIn: directory || 'videos',
    });
    await directoryStorage(chosen, true);
    directory = chosen;
    drawSettings();
    settingsMessage(`Domyślny folder: ${directory.name}.`);
    return chosen;
}

async function chooseDestination(filename, selected) {
    if (selected.askEveryTime) {
        const handle = await window.showSaveFilePicker({
            id: 'nvr-save-recording', startIn: directory || 'videos', suggestedName: filename,
            excludeAcceptAllOption: true,
            types: [{ description: `Nagranie ${selected.format.toUpperCase()}`,
                      accept: { [FORMATS[selected.format]]: ['.' + selected.format] } }],
        });
        if (!handle.name.toLowerCase().endsWith('.' + selected.format)) {
            throw new Error(`Nazwa pliku musi kończyć się na .${selected.format}.`);
        }
        return { handle, name: handle.name };
    }
    if (!directory) await chooseDirectory();
    const permission = { mode: 'readwrite' };
    if (await directory.queryPermission(permission) !== 'granted'
        && await directory.requestPermission(permission) !== 'granted') {
        throw new Error('Nie udzielono dostępu do wybranego folderu. Wybierz folder ponownie w Ustawieniach.');
    }
    return { directory, name: filename };
}

function transferMessage(text, state = 'working') {
    const notice = element('download-notice');
    notice.hidden = false;
    notice.dataset.state = state;
    element('download-transfer-message').textContent = text;
    element('download-cancel').hidden = state !== 'working';
    element('download-dismiss').hidden = state === 'working';
    element('download-progress').hidden = state !== 'working';
}

async function saveResponse(response, destination, controller) {
    let target = destination;
    let created = false;
    try {
        if (destination.directory) {
            target = { ...destination, ...await createUniqueFile(destination.directory, destination.name) };
            created = true;
        }
        await streamToFile(response, target.handle, (received, total) => {
            const progress = element('download-progress');
            if (total) { progress.max = total; progress.value = received; }
            transferMessage(`Zapisywanie: ${(received / 1048576).toFixed(1)}${total ? ' / ' + (total / 1048576).toFixed(1) : ''} MB`);
        }, controller.signal);
        transferMessage(`Zapisano: ${target.directory ? target.directory.name + ' / ' : ''}${target.name}`, 'success');
    } catch (error) {
        if (created) {
            try { await destination.directory.removeEntry(target.name); } catch (_) {}
        }
        throw error;
    }
}

async function requestDownload(params) {
    if (activeDownload) { transferMessage('Trwa już zapisywanie nagrania. Poczekaj na zakończenie.'); return; }
    if (!ready) { transferMessage('Trwa wczytywanie ustawień. Spróbuj za chwilę.', 'error'); return; }
    if (!supported()) {
        transferMessage(window.isSecureContext
            ? 'Kontrolowany zapis wymaga przeglądarki obsługującej wybór folderów, np. Chrome lub Edge. Nie rozpoczęto pobierania.'
            : 'Aby wybrać miejsce zapisu na swoim komputerze, otwórz aplikację przez HTTPS lub localhost.', 'error');
        return;
    }
    const selected = { ...settings };
    const controller = new AbortController();
    activeDownload = controller;
    try {
        // Pick the destination during the click's user activation, before any
        // network request. Never fall back to a browser-controlled download.
        const destination = await chooseDestination(suggestedFilename(params, selected.format), selected);
        if (controller.signal.aborted) throw new DOMException('Anulowano.', 'AbortError');
        element('download-progress').removeAttribute('value');
        transferMessage('Przygotowywanie nagrania… Dłuższy materiał może wymagać kilku minut.');
        const query = new URLSearchParams({ ...params, format: selected.format, quality: selected.quality });
        const response = await fetch('/api/recordings/download?' + query, { signal: controller.signal, cache: 'no-store' });
        if (!response.ok) {
            let message = `Nie udało się pobrać nagrania (${response.status}).`;
            try { message = (await response.json()).detail || message; } catch (_) {}
            throw new Error(message);
        }
        const save = () => saveResponse(response, destination, controller);
        // Serialize filename allocation across tabs sharing the chosen folder.
        if (navigator.locks) await navigator.locks.request('nvr-recording-save', save);
        else await save();
    } catch (error) {
        transferMessage(error.name === 'AbortError' ? 'Anulowano pobieranie.' : error.message || 'Nie udało się zapisać nagrania.',
                        error.name === 'AbortError' ? 'cancelled' : 'error');
    } finally {
        activeDownload = null;
    }
}

async function initialize() {
    try { settings = normalizeSettings(JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}')); } catch (_) {}
    try { directory = await directoryStorage(); } catch (_) {
        settingsMessage('Nie można zapamiętać folderu w tej przeglądarce. Sprawdź dostęp do pamięci witryny.', true);
    }
    drawSettings();
    ready = true;
    if (!supported()) {
        element('download-choose-folder').disabled = true;
        element('download-browser-warning').hidden = false;
        element('download-browser-warning').textContent = window.isSecureContext
            ? 'Ta przeglądarka nie obsługuje wyboru miejsca zapisu. Użyj aktualnego Chrome lub Edge. Nagrania nie będą zapisywane w przypadkowym folderze.'
            : 'Przy dostępie zdalnym wybór folderu wymaga HTTPS. Lokalnie użyj adresu localhost lub 127.0.0.1.';
    }
    ['download-ask', 'download-format', 'download-quality'].forEach(id => element(id).addEventListener('change', saveSettings));
    element('download-choose-folder').addEventListener('click', async () => {
        try { await chooseDirectory(); } catch (error) {
            if (error.name !== 'AbortError') settingsMessage(error.message || 'Nie udało się wybrać folderu.', true);
        }
    });
    element('download-cancel').addEventListener('click', () => activeDownload?.abort());
    element('download-dismiss').addEventListener('click', () => { element('download-notice').hidden = true; });
}

if (typeof document !== 'undefined') {
    window.requestRecordingDownload = requestDownload;
    initialize();
}
