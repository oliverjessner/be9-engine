import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const browsers = process.argv.length === 2 ? ['chromium', 'firefox', 'webkit'] : process.argv.slice(2);
if (!browsers.length || browsers.some(name => !['chromium', 'firefox', 'webkit'].includes(name))) {
    console.error('Invalid browser matrix options.'); process.exitCode = 2;
} else {
    for (const browser of browsers) for (const bundle of ['source', 'esm', 'iife']) {
        const result = await new Promise(resolve => {
            const child = spawn(process.execPath, ['test/run-browser.mjs', '--browser', browser, '--bundle', bundle], { cwd: root, stdio: 'inherit' });
            child.on('error', () => resolve(2)); child.on('exit', code => resolve(code ?? 2));
        });
        process.exitCode = Math.max(process.exitCode || 0, result);
    }
}
