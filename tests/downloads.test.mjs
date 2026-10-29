import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeSettings, suggestedFilename, createUniqueFile, streamToFile } from '../static/downloads.mjs';

test('stored settings reject unknown formats and preserve explicit choices', () => {
    assert.deepEqual(normalizeSettings({ format: 'exe', quality: 'invalid', askEveryTime: 'yes' }),
        { format: 'avi', quality: 'original', askEveryTime: false });
    assert.deepEqual(normalizeSettings({ format: 'mp4', quality: '720p', askEveryTime: true }),
        { format: 'mp4', quality: '720p', askEveryTime: true });
});

test('suggested filename is portable between Windows and Unix clients', () => {
    const name = suggestedFilename({ dvr_id: '3', channel: '13', date: '2026-10-28', start_time: '03:00:00', end_time: '03:10:00' }, 'mp4');
    assert.ok(name.endsWith('.mp4'));
    assert.doesNotMatch(name, /[\\/:*?"<>|\x00-\x1f]/);
});

test('existing recordings are not overwritten during default-directory saves', async () => {
    const files = new Set(['recording.mp4', 'recording (1).mp4']);
    const directory = { async getFileHandle(name, options) {
        if (files.has(name)) return { name };
        if (!options?.create) throw new DOMException('', 'NotFoundError');
        files.add(name);
        return { name };
    } };
    assert.equal((await createUniqueFile(directory, 'recording.mp4')).name, 'recording (2).mp4');
    assert.equal(files.size, 3);
});

test('denied folder access fails without choosing another location', async () => {
    await assert.rejects(createUniqueFile({ getFileHandle() {
        throw new DOMException('', 'NotAllowedError');
    } }, 'recording.avi'), { name: 'NotAllowedError' });
});

function transactionalFile() {
    const state = { value: 'existing file', closed: false, aborted: false };
    return { state, handle: { async createWritable() {
        const chunks = [];
        return {
            async write(chunk) { chunks.push(Buffer.from(chunk)); },
            async close() { state.value = Buffer.concat(chunks).toString(); state.closed = true; },
            async abort() { state.aborted = true; },
        };
    } } };
}

test('chunks are committed only after the entire response is received', async () => {
    const { state, handle } = transactionalFile();
    const response = new Response(new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode('first '));
        controller.enqueue(new TextEncoder().encode('second'));
        controller.close();
    } }), { headers: { 'Content-Length': '12' } });
    assert.equal(await streamToFile(response, handle), 12);
    assert.equal(state.value, 'first second');
    assert.equal(state.closed, true);
    assert.equal(state.aborted, false);
});

test('truncated response aborts the write and preserves an existing file', async () => {
    const { state, handle } = transactionalFile();
    await assert.rejects(streamToFile(new Response('short', { headers: { 'Content-Length': '100' } }), handle));
    assert.equal(state.value, 'existing file');
    assert.equal(state.closed, false);
    assert.equal(state.aborted, true);
});

test('cancellation aborts the write and preserves the previous file', async () => {
    const { state, handle } = transactionalFile();
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(streamToFile(new Response('data'), handle, () => {}, controller.signal), { name: 'AbortError' });
    assert.equal(state.value, 'existing file');
    assert.equal(state.aborted, true);
});

test('a failed transfer never commits partial data', async () => {
    const { state, handle } = transactionalFile();
    const response = new Response(new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode('partial'));
        controller.error(new Error('connection lost'));
    } }));
    await assert.rejects(streamToFile(response, handle), /connection lost/);
    assert.equal(state.value, 'existing file');
    assert.equal(state.aborted, true);
});
