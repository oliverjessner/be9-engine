// Compare build output to the exact pre-build bytes, including local changes.
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const files = ['dist/bundle.mjs', 'dist/bundle.min.js'];
try {
    const before = await Promise.all(files.map(file => readFile(new URL('../' + file, import.meta.url))));
    const status = await new Promise(resolve => {
        const child = spawn('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
        child.on('error', () => resolve(2)); child.on('exit', code => resolve(code ?? 2));
    });
    if (status !== 0) throw new Error();
    const after = await Promise.all(files.map(file => readFile(new URL('../' + file, import.meta.url))));
    if (before.some((bytes, i) => !bytes.equals(after[i]))) {
        console.error('Distribution differs from a fresh build. Regenerate and commit dist/.'); process.exitCode = 1;
    } else console.log('Distribution matches a fresh build.');
} catch { console.error('Build verification failed.'); process.exitCode = 2; }
