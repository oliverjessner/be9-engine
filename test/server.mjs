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
    ...['suite', 'database', 'participants', 'basics', 'text', 'image', 'group', 'exceptions', 'aes', 'persistence', 'key-protection', 'trust', 'v2', 'legacy-fixture', 'encoding']
        .map(name => ['/test/' + name + '.mjs', ['test/' + name + '.mjs', 'text/javascript']]),
    ...['bundle', 'util', 'persistence', 'key-store', 'crypto-keys', 'trust', 'v2', 'encoding', 'limits', 'aes', 'usage'].map(name => ['/lib/' + name + '.mjs', ['lib/' + name + '.mjs', 'text/javascript']]),
]);

export async function createTestServer(port = 0) {
    const server = createServer(async (request, response) => {
        const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
        const asset = assets.get(pathname);
        if (request.method !== 'GET' || !asset) {
            response.writeHead(404).end();
            return;
        }
        try {
            const body = await readFile(resolve(root, asset[0]));
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
