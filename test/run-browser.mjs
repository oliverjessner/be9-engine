import { chromium } from 'playwright';
import { createTestServer } from './server.mjs';

let server;
let browser;
let phase = 'server startup';
try {
    const args = process.argv.slice(2);
    if (args.length && (args.length !== 2 || args[0] !== '--bundle' || !['source', 'esm', 'iife'].includes(args[1]))) throw new Error('Invalid test runner options');
    const bundle = args[1] || 'source';
    server = await createTestServer(0, { bundle });
    phase = 'browser launch (install with npx playwright install chromium)';
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    let browserErrors = 0;
    let resourceFailures = 0;
    // Count failures without logging exception messages, console data or stacks.
    page.on('pageerror', () => { browserErrors++; });
    page.on('requestfailed', () => { resourceFailures++; });
    page.on('response', response => { if (response.status() >= 400) resourceFailures++; });
    const origin = new URL(server.url).origin;
    await context.route('**/*', route => {
        if (new URL(route.request().url()).origin === origin) {
            return route.continue();
        }
        resourceFailures++;
        return route.abort();
    });
    phase = 'test page load';
    await page.goto(server.url);
    phase = 'native browser capabilities';
    const nativeAvailable = await page.evaluate(() =>
        window.isSecureContext && !!window.crypto?.subtle && !!window.indexedDB);
    if (!nativeAvailable) {
        throw new Error('Browser capabilities unavailable');
    }
    phase = 'QUnit completion';
    // Event-driven completion; the timer is a failure deadline, not a readiness wait.
    const result = await page.evaluate(() => new Promise((resolve, reject) => {
        const deadline = setTimeout(() => reject(new Error('Browser suite deadline exceeded')), 60000);
        if (!window.__be9TestDone) {
            clearTimeout(deadline);
            reject(new Error('Browser suite not registered'));
            return;
        }
        window.__be9TestDone.then(value => {
            clearTimeout(deadline);
            resolve(value);
        }, reject);
    }));
    for (const test of result.tests) {
        console.log((test.failed ? 'FAIL' : 'PASS') + ' ' + test.module + ' :: ' + test.name +
            ' (' + test.passed + '/' + test.total + ' assertions)');
    }
    const failedTests = result.tests.filter(test => test.failed).length;
    console.log('Bundle: ' + bundle);
    console.log('Tests: ' + result.tests.length + ', failed: ' + failedTests +
        '; assertions: ' + result.assertions.passed + '/' + result.assertions.total +
        '; browser errors: ' + browserErrors + '; resource failures: ' + resourceFailures);
    const incomplete = result.tests.length === 0 || result.tests.some(test => test.total === 0);
    process.exitCode = browserErrors || resourceFailures || incomplete ? 2 : failedTests || result.assertions.failed ? 1 : 0;
} catch {
    // Do not print raw browser errors: test inputs or key data could appear there.
    console.error('Browser test infrastructure failed during ' + phase + '.');
    process.exitCode = 2;
} finally {
    const cleanup = await Promise.allSettled([
        browser ? browser.close() : Promise.resolve(),
        server ? server.close() : Promise.resolve(),
    ]);
    if (cleanup.some(result => result.status === 'rejected')) {
        console.error('Browser test infrastructure cleanup failed.');
        process.exitCode = 2;
    }
}
