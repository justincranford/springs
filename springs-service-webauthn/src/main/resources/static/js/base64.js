function base64urlToUint8Array(base64url) {
    // base64url to base64
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
    const base64 = base64url + padding;

    // base64 to binary
    const binaryString = atob(base64);

    // binary to byte array
    const bytes = [];
    for (let i = 0; i < binaryString.length; i++) {
        bytes.push(binaryString.charCodeAt(i));
    }

    // byte array to Uint8Array
    return new Uint8Array(bytes);
}

function uint8ArrayToBase64url(uint8Array) {
    // Uint8Array to a binary string
    let binaryString = '';
    for (let i = 0; i < uint8Array.length; i++) {
        binaryString += String.fromCharCode(uint8Array[i]);
    }

    // Encode the binary string as Base64
    const base64String = btoa(binaryString);

    // Convert Base64 to Base64URL format
    return base64String
        .replace(/\+/g, '-')  // Replace + with -
        .replace(/\//g, '_')  // Replace / with _
        .replace(/=+$/, '');  // Remove padding '='
}
