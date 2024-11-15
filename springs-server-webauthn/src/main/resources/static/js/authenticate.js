function getAuthenticationStartClient(username) {
    const authenticationStartClient = username == null ? { } : { username };
    console.log('authenticationStartClient:', JSON.stringify(authenticationStartClient));
    return authenticationStartClient;
}

async function getAuthenticationStartServer(authenticationStartClient) {
    const httpResponse = await fetch('/api/v1/authenticate/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept':       'application/json; charset=UTF-8'
        },
        body: JSON.stringify(authenticationStartClient)
    });
    if (!httpResponse.ok) throw new Error(`Authentication request failed: ${httpResponse.statusText}`);
    const authenticationStartServer = await httpResponse.json();
    console.log('authenticationStartServer:', JSON.stringify(authenticationStartServer));
    return await authenticationStartServer;
}

function toPublicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions) {
    publicKeyCredentialRequestOptions.challenge = base64urlToUint8Array(publicKeyCredentialRequestOptions.challenge);
    if (Array.isArray(publicKeyCredentialRequestOptions.allowCredentials)) {
        publicKeyCredentialRequestOptions.allowCredentials.forEach(allowCredential => {
            console.log('allowCredential:', JSON.stringify(allowCredential));
            allowCredential.id = base64urlToUint8Array(allowCredential.id);
        });
    }
    const requestOptions = { publicKey: publicKeyCredentialRequestOptions };
    console.log('requestOptions:', JSON.stringify(requestOptions));
    return requestOptions;
}

async function navigatorCredentialsGet(publicKeyCredentialRequestOptions) {
    const publicKeyCredential = await navigator.credentials.get(publicKeyCredentialRequestOptions);
    if (!publicKeyCredential) throw new Error('Failed to get credential.');
    console.log('publicKeyCredential:', JSON.stringify(publicKeyCredential));
    return publicKeyCredential;
}

function fromPublicKeyCredential(sessionToken, publicKeyCredential) {
    const authenticationFinishClient  = {
        sessionToken: sessionToken,
        publicKeyCredentialEncoded: JSON.stringify(publicKeyCredential),
    };
    console.log('authenticationFinishClient:', JSON.stringify(authenticationFinishClient));
    return authenticationFinishClient;
}

async function getAuthenticationFinishServer(authenticationFinishClient) {
    const httpResponse = await fetch('/api/v1/authenticate/finish', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept':       'application/json; charset=UTF-8'
        },
        body: JSON.stringify(authenticationFinishClient)
    });

    if (!httpResponse.ok) throw new Error(`Request failed: ${httpResponse.statusText}`);
    const authenticationFinishServer = await httpResponse.json();
    console.log('authenticationFinishServer:', JSON.stringify(authenticationFinishServer));
    return authenticationFinishServer;
}

async function authenticate(authenticationStartClient) {
    try {
        const authenticationStartServer         = await getAuthenticationStartServer(authenticationStartClient);
        const publicKeyCredentialRequestOptions = toPublicKeyCredentialRequestOptions(authenticationStartServer.publicKeyCredentialRequestOptions);
        const publicKeyCredential               = await navigatorCredentialsGet(publicKeyCredentialRequestOptions);
        const authenticationFinishClient        = fromPublicKeyCredential(authenticationStartServer.sessionToken, publicKeyCredential);
        const authenticationFinishServer        = await getAuthenticationFinishServer(authenticationFinishClient);
		if (authenticationFinishServer != null) {
			alert('authenticationFinishServer:', authenticationFinishServer);
		}
    } catch (error) {
        console.error('Authentication Error:', error);
        alert(error);
    }
}
