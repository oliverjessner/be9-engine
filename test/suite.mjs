QUnit.config.autostart = false;
QUnit.config.reorder = false;
QUnit.config.testTimeout = 15000;

const tests = [];
let resolveDone;
window.__be8TestDone = new Promise(resolve => { resolveDone = resolve; });
QUnit.testDone(details => {
    // Do not serialize assertion actual/expected values, exceptions, stacks,
    // console output, or DOM snapshots: they may contain cryptographic data.
    tests.push({
        module: details.module,
        name: details.name,
        failed: details.failed,
        passed: details.passed,
        total: details.total,
    });
});
QUnit.done(details => resolveDone({
    tests,
    assertions: { passed: details.passed, failed: details.failed, total: details.total },
}));

await import('./basics.mjs');
await import('./text.mjs');
await import('./group.mjs');
await import('./image.mjs');
await import('./exceptions.mjs');
await import('./aes.mjs');
await import('./persistence.mjs');
await import('./key-protection.mjs');
await import('./trust.mjs');
await import('./v2.mjs');
await import('./encoding.mjs');
await import('./envelope.mjs');
await import('./replay.mjs');
await import('./panic.mjs');
QUnit.start();
