// generates an Initialization vector
export function generateIV () {
    // a nonce (number once) is an arbitrary string that can be used just once in a cryptographic communication
    const nonce = self.crypto.randomUUID();
    return new TextEncoder().encode(nonce);
}

export function arrayBufferToBase64 (buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return window.btoa(binary);
}

export function getTypeOfKey (id) {
    if (!id) {
        throw new Error('engine: id is required in getTypeOfKey');
    }
    if (id.charAt(0) === 'g') {
        return 'group';
    }
    if (id.charAt(0) === 'c') {
        return 'channel';
    }

    return 'dialog';
}
