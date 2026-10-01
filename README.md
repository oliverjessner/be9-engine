# be8-engine
Be8 uses a Elliptic Curve Diffie-Hellman 384 bit prime curve encryption to ensure
safe e2ee communications.

## usage
The constructer takes one parameter the accID. 
In case of no id passed it throws an error. ID has to be
a string that is a number.

```javascript
const be8 = new Be8('1');
```

## hasGeneratedKeys()

Checks if the object already generated keys and if they are stored.
Returns a boolean.

```javascript
be8.hasGeneratedKeys();
```

## getAccID
Return the accID.

```javascript
be8.getAccID();
```

## addPublicKeys (publicKeys = [])
Takes an array of public key accid key pair values and calls addPublicKey for every pair. 

```javascript 
const publicKeys = [{
    accID: '',
    publicKey: {
        crv: 'P-384'
        ext: 'true'
        key_ops: ['deriveKey', 'deriveBits']
        kty: 'EC'
        x: 'A8QYrJJeE5iEshV3ycX2DNvgltSq9NHQypmkDybLHII'
        y: 'IxbSJxIfvjuBvyTlNt_RToCgYzqvBHsIvWVB8bW-EFs'
    }
}]; 

be8.addPublicKeys(publicKeys);
```

## addPublicKey(accID, key)
Adds an accID publicKey pair value to a private map.

```javascript
const publicKey = {
    accID: '10101',
    publicKey: {
        crv: 'P-384'
        ext: 'true'
        key_ops: ['deriveKey', 'deriveBits']
        kty: 'EC'
        x: 'A8QYrJJeE5iEshV3ycX2DNvgltSq9NHQypmkDybLHII'
        y: 'IxbSJxIfvjuBvyTlNt_RToCgYzqvBHsIvWVB8bW-EFs'
    }
};

be8.addPublicKey(publicKey);
```

## addGroupKey(groupID, key)
Group keys are stored seperately from the other keys.

```javascript
be8.addGroupKey('g10300', {});
```

## async generatePrivAndPubKey()
Returns freshly generated private and public keys. Automatically stores the keys in the localstorage.

```javascript
const [publicKey, privateKey] = await be8.generatePrivAndPubKey();
```

## async generateGroupKeys
Generates a group key and stores it in a private map.

```javascript
const [publicKey, privateKey] = await be8.generateGroupKeys();
```

## async getDerivedKey(publicKey, privateKey)
Generates a derived key out of the public and private key. 

```javascript
const privateKey = {};
const publicKey = {};
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
```

## async encryptText(derivedKey, text = '')
After creating a [derivedKey](#async-getderivedkeypublickeyjwk-privatekeyjwk) we can start to encrypt text messages. encryptText returns a cipherText and a iv (Initialization vector).
 
```javascript
const text = 'Hello World';
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
const { cipherText, iv } = await be8.encryptText(derivedKey, text);
```

## async decryptText(derivedKey, cipherText, iv)
With the help of the key, the cipherText and an iv, we can decrypt messages.

```javascript
const cipherText = 'ASDASD9324/&§$jn';
const iv = '213210931249713409';
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
const text = await be8.decryptText(derivedKey, cipherText);
```

## encryptTextSimple(accIDSender, accIDReceiver, text)
encryptTextSimple is a compound function of [encryptText](#async-encrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-privatekey). It uses the ids instead of keys. 
The derivedKey is generated inside the function.

```javascript
const accIDSender = '101010';
const accIDReceiver = '101011';
const text = 'Hello World';
const cipherText = await be8.encryptTextSimple(accIDSender, accIDReceiver, text);
```

## async decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv)
decryptTextSimple is a compound function of [decryptText](#async-decrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-privatekey). It uses the ids instead of keys. 
The derivedKey is generated inside the function.

```javascript
const accIDSender = '101010';
const accIDReceiver = '101011';
const cipherText = 'sadadwWE=)AWLKASDS';
const iv = '2139484765456789';
const cipherText = await be8.decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv);
```

## async encryptImage(derivedKey, base64Image)
Accepts the derivedKey and an image encoded as base64 so it can creates a "cipherImage" and 
an iv.

```javascript
const { cipherImage, iv } = await be8.encryptImage(derivedKey, base64Image);
```

## async decryptImage(derivedKey, cipherImage, iv)
Uses the derivedKey, the cipherImage and the iv to decrypt a base64Image.

```javascript
const base64Image = await be8.encryptImage(derivedKey, cipherImage, iv);
```

## async encryptImageSimple (accIDSender, accIDReceiver, base64Image)

```javascript
const base64Image = await be8.encryptImageSimple(accIDSender, accIDReceiver, base64Image);
```

## async decryptImageSimple (accIDSender, accIDReceiver, cipherImage, iv)


```javascript
const base64Image = await be8.decryptImageSimple(accIDSender, accIDReceiver, cipherImage, iv);
```

## Scripts
### building
Rollup creates two versions one is a esm6 version and a minified iife one.
Both can be found in /dist.

```bash
npm run build
```

### Testing

The automated QUnit suite runs the source modules in headless Chromium with
native WebCrypto and IndexedDB. It requires Node.js 20 or newer. Install the
development dependencies and the Playwright browser once:

```bash
npm ci
npx playwright install chromium
```

On Linux CI hosts, use `npx playwright install --with-deps chromium` when browser
system libraries are missing. Playwright is a development dependency only.
See the [Playwright library documentation](https://playwright.dev/docs/library).

Run the full suite:

```bash
npm test
```

Exit codes are `0` for a complete passing suite, `1` for failed assertions, and
`2` for browser, resource, capability, timeout, or infrastructure errors. Output
contains test names and assertion counts; assertion values, browser exceptions,
console data, and stacks are not copied into the runner output.

For the interactive QUnit page, run `npm run test:manual` and open
http://127.0.0.1:3000/. QUnit assets are served locally, with no CDN dependency.
The loopback server only serves test assets; participants exchange public keys,
public metadata, and encrypted packets directly in test code, without networking.

Each test creates separate, uniquely named databases for Alice, Bob, and Eve.
Each participant retains its own private key. Integration tests derive a key
independently at each endpoint or use the simplified API on the actual recipient.
Private JWKs and derived AES keys are never exchanged between participants.
Readiness and cleanup use native IndexedDB open, request, complete, and abort
events, rather than fixed delays. Only the test-created databases are deleted.

`test/aes.mjs` contains separate single-instance AES unit tests. Group tests
exercise pairwise ECDH with Alice's local private group key, Bob's own private
identity key, and the corresponding exchanged public keys. They do not claim
broadcast encryption, membership enforcement, invitation handling, or protection
based on group membership. Different versions must authenticate independently;
old installed versions remain available.

#### Current findings and limits

The Chromium run of the revised suite reports 36 tests, with 34 passing and two
failing (129 of 131 assertions passing, exit code `1`):

- `generatePrivAndPubKey()` resolves while its native write transactions are
  still pending. It awaits `transaction.complete`, which does not exist on
  native IndexedDB transactions.
- `addPublicKeys()` resolves while its write transaction is still pending.
  Its `map` callback does not return a promise for a write or transaction.

These contract tests remain ordinary failing assertions; they are not skipped,
marked as expected failures, or hidden by a persistence mock. The test database
adapter observes and forwards native transactions without adding a `.complete`
property. Fixtures explicitly await those real transactions to test reopening
after completed storage. Consequently, successful reopen tests do not establish
that awaiting the current engine write methods guarantees a commit.

Generated private group keys currently remain in the owner's in-memory state;
the group reopen test covers the recipient's explicitly stored public group keys.
The suite covers the existing ECDH/AES-GCM and IV format. It does not define or
implement a v2 KDF, nonce, or envelope profile, legacy migration, or additional
security features. It tests Chromium only and is not a security audit.

The engine API and build outputs are unchanged. Tooling changes: `npm test` now
finishes automatically with an exit code; use `npm run test:manual` for the
previous interactive test-server workflow. Tests import `lib/` directly, so the
suite checks current source without requiring or modifying `dist/`.
