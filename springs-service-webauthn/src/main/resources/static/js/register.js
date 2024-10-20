function getRegistrationStartClient(username, displayName, credentialNickname, residentKeyRequirement) {
    const registrationStartClient = { username, displayName, credentialNickname, residentKeyRequirement };
    console.log('registrationStartClient:', JSON.stringify(registrationStartClient));
    return registrationStartClient;
}

async function getRegistrationStartServer(registrationStartClient) {
    const httpResponse = await fetch('/api/v1/register/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept':       'application/json; charset=UTF-8'
        },
        body: JSON.stringify(registrationStartClient)
    });
    if (!httpResponse.ok) throw new Error(`Registration request failed: ${httpResponse.statusText}`);
    const registrationStartServer = await httpResponse.json();
    console.log('registrationStartServer:', JSON.stringify(registrationStartServer));
    return await registrationStartServer;
}

function toPublicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions) {
    publicKeyCredentialCreationOptions.user.id   = base64urlToUint8Array(publicKeyCredentialCreationOptions.user.id);
    publicKeyCredentialCreationOptions.challenge = base64urlToUint8Array(publicKeyCredentialCreationOptions.challenge);
    if (Array.isArray(publicKeyCredentialCreationOptions.excludeCredentials)) {
        publicKeyCredentialCreationOptions.excludeCredentials.forEach(excludeCredential => {
            console.log('excludeCredential:', JSON.stringify(excludeCredential));
            excludeCredential.id = base64urlToUint8Array(excludeCredential.id);
        });
    }
    const creationOptions = { publicKey: publicKeyCredentialCreationOptions };
    console.log('creationOptions:', JSON.stringify(creationOptions));
    return creationOptions;
}

async function navigatorCredentialsCreate(publicKeyCredentialCreationOptions) {
    const publicKeyCredential = await navigator.credentials.create(publicKeyCredentialCreationOptions);
    if (!publicKeyCredential) throw new Error('Failed to create credential.');
    console.log('publicKeyCredential:', JSON.stringify(publicKeyCredential));
    return publicKeyCredential;
}

function fromPublicKeyCredential(sessionToken, publicKeyCredential) {
    const registrationFinishClient  = {
        sessionToken: sessionToken,
        publicKeyCredentialEncoded: JSON.stringify(publicKeyCredential),
    };
    console.log('registrationFinishClient:', JSON.stringify(registrationFinishClient));
    return registrationFinishClient;
}

async function getRegistrationFinishServer(registrationFinishClient) {
    const httpResponse = await fetch('/api/v1/register/finish', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept':       'application/json; charset=UTF-8'
        },
        body: JSON.stringify(registrationFinishClient)
    });

    if (!httpResponse.ok) throw new Error(`Request failed: ${httpResponse.statusText}`);
    const registrationFinishServer = await httpResponse.json();
    console.log('registrationFinishServer:', JSON.stringify(registrationFinishServer));
    return registrationFinishServer;
}

async function register(registrationStartClient) {
    try {
        const registrationStartServer            = await getRegistrationStartServer(registrationStartClient);
        const publicKeyCredentialCreationOptions = toPublicKeyCredentialCreationOptions(registrationStartServer.publicKeyCredentialCreationOptions);
        const publicKeyCredential                = await navigatorCredentialsCreate(publicKeyCredentialCreationOptions);
        const registrationFinishClient           = fromPublicKeyCredential(registrationStartServer.sessionToken, publicKeyCredential);
        const registrationFinishServer           = await getRegistrationFinishServer(registrationFinishClient);
		if (registrationFinishServer != null) {
			alert('registrationFinishServer:', registrationFinishServer);
		}
    } catch (error) {
        console.error('Registration Error:', error);
        alert(error);
    }
}
