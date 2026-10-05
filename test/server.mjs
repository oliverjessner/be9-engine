// Local static test tooling only. No engine transport or participant API.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const assets = new Map([
    ['/', ['test/index.html', 'text/html']],
    ['/vendor/qunit.js', ['node_modules/qunit/qunit/qunit.js', 'text/javascript']],
    ['/vendor/qunit.css', ['node_modules/qunit/qunit/qunit.css', 'text/css']],
    ...['suite', 'database', 'participants', 'basics', 'text', 'image', 'group', 'exceptions', 'aes', 'persistence', 'key-protection', 'trust', 'v2', 'legacy-fixture', 'encoding', 'envelope', 'replay', 'panic', 'panic-worker', 'be8-legacy-vectors', 'be8-legacy-fixture', 'rename', 'ratchet', 'signed-group', 'session-fixture', 'ratchet-vector', 'ratchet-worker']
        .map(name => ['/test/' + name + '.mjs', ['test/' + name + '.mjs', 'text/javascript']]),
    ...['bundle', 'util', 'persistence', 'key-store', 'crypto-keys', 'trust', 'v2', 'encoding', 'limits', 'aes', 'usage', 'group-profile', 'groups', 'legacy-be8', 'envelope', 'replay', 'protocol', 'signing', 'session', 'session-store', 'ratchet', 'ratchet-envelope', 'signed-group'].map(name => ['/lib/' + name + '.mjs', ['lib/' + name + '.mjs', 'text/javascript']]),
]);

const helpers = ['upgradeBe9Schema', 'migrateBe8Schema', 'encodeBe8DerivationInfo', 'encodeBe8EnvelopeAAD', 'STORES', 'jwkThumbprint', 'V2_SUITE', 'GROUP_SUITE', 'encodeV2DerivationInfo', 'encodeBase64url', 'decodeBase64url', 'V2_LIMITS', 'REPLAY_WINDOW', 'encodeEnvelopeAAD', 'RATCHET_SUITE', 'SIGNED_GROUP_SUITE', 'SESSION_LIMITS', 'encodeRatchetAAD'];
export async function createTestServer(port = 0, { bundle = 'source' } = {}) {
    if (!['source', 'esm', 'iife'].includes(bundle)) throw new Error('Unknown test bundle');
    const selected = new Map(assets);
    if (bundle !== 'source') selected.set('/lib/bundle.mjs', [bundle === 'esm' ? 'dist/bundle.mjs' : 'dist/bundle.min.js', 'text/javascript']);
    const server = createServer(async (request, response) => {
        const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
        const asset = selected.get(pathname);
        if (request.method !== 'GET' || !asset) {
            response.writeHead(404).end();
            return;
        }
        try {
            let body = await readFile(resolve(root, asset[0]));
            if (bundle === 'iife' && pathname === '/lib/bundle.mjs') {
                // Evaluate the generated IIFE unchanged, then expose its callable
                // constructor/statics to the ESM tests (also in module workers).
                body = body.toString() + '\nconst Be9 = be9; export default Be9;\n' + helpers.map(name => 'export const ' + name + ' = Be9.' + name + ';').join('\n');
            }
            response.writeHead(200, { 'Content-Type': asset[1], 'Cache-Control': 'no-store' }).end(body);
        } catch {
            response.writeHead(500).end('Test asset unavailable');
        }
    });
    await new Promise((resolveListen, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolveListen);
    });
    return {
        url: 'http://127.0.0.1:' + server.address().port + '/',
        async close() {
            await new Promise((resolveClose, reject) => server.close(error => error ? reject(error) : resolveClose()));
        },
    };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const server = await createTestServer(3000);
    console.log('Open ' + server.url);
}
