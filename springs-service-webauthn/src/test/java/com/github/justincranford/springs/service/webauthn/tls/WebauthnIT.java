package com.github.justincranford.springs.service.webauthn.tls;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.service.webauthn.AbstractIT;
import com.github.justincranford.springs.service.webauthn.actions.data.ActionsResponse;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings("nls")
public class WebauthnIT extends AbstractIT {
	@Test
	void testHome() {
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + "/index.html", String.class);
		assertThat(response).contains("WebAuthn");
	}

	@Test
	void testActionsApi() {
		final ActionsResponse response = RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/api/v1", ActionsResponse.class);
		log.info("response: {}", response);
		assertThat(response).isNotNull();
	}

	@Test
	void parseRegistrationRequest() throws JsonMappingException, JsonProcessingException {
		final RegistrationRequest  registrationRequest  = objectMapper().readValue(this.registrationRequestJson, RegistrationRequest.class);
	}

	@Test
	void parseRegistrationResponse() throws JsonMappingException, JsonProcessingException {
		final RegistrationResponse registrationResponse = objectMapper().readValue(this.registrationResponseJson, RegistrationResponse.class);
	}

	final String registrationRequestJson = """
		{
		  "success": true,
		  "userIdentity": {
		    "name": "My Username",
		    "displayName": "My Display Name",
		    "id": "qOifpDaeSPD6oQWUdJsDg92ET8_0O8NEFCC4CkQghCI"
		  },
		  "username": "My Username",
		  "displayName": "My Display Name",
		  "credentialNickname": "My Credential Nickname",
		  "sessionToken": "RegSessionToken3K9g51Roedvuoo22c9yf6Q",
		  "request": {
		    "publicKeyCredentialCreationOptions": {
		      "rp": {
		        "name": "springs-service-webauthn",
		        "id": "localhost"
		      },
		      "user": {
		        "name": "My Username",
		        "displayName": "My Display Name",
		        "id": "qOifpDaeSPD6oQWUdJsDg92ET8_0O8NEFCC4CkQghCI"
		      },
		      "challenge": "JWu6kSRT2fWKFqlVnB_BTtlHl1jkF5pm4i5M4ZNeZDg",
		      "pubKeyCredParams": [
		        {
		          "alg": -8,
		          "type": "public-key"
		        },
		        {
		          "alg": -7,
		          "type": "public-key"
		        },
		        {
		          "alg": -257,
		          "type": "public-key"
		        }
		      ],
		      "timeout": 300000,
		      "authenticatorSelection": {
		        "authenticatorAttachment": "platform",
		        "requireResidentKey": false,
		        "residentKey": "preferred",
		        "userVerification": "discouraged"
		      },
		      "attestation": "none",
		      "extensions": {
		        "appidExclude": "https://localhost",
		        "credProps": true
		      }
		    }
		  },
		  "actions": {
		    "finish": "https://localhost:8443/api/v1/register/finish"
		  }
		}
		""";

	final String registrationResponseJson = """
		{
		  "credential": {
		    "type": "public-key",
		    "id": "eKrEP7FSlMvzIEl1RidKvg",
		    "rawId": "eKrEP7FSlMvzIEl1RidKvg",
		    "response": {
		      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSld1NmtTUlQyZldLRnFsVm5CX0JUdGxIbDFqa0Y1cG00aTVNNFpOZVpEZyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
		      "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NZAAAAAOqbjWZNAR0hPOS2tIy1ddQAEHiqxD-xUpTL8yBJdUYnSr6lAQIDJiABIVgglKa8k-O9LIf2qw2LdxweOymg2_u2gijJptUA-8dC0ooiWCA6nfA2sZBQz7f4JXDuaSzXkPh0RVTQ3InYv0EwwM7Yqw",
		      "transports": [
		        "hybrid",
		        "internal"
		      ]
		    },
		    "clientExtensionResults": {
		      "credProps": {
		        "rk": true
		      }
		    }
		  },
		  "sessionToken": "RegSessionToken3K9g51Roedvuoo22c9yf6Q"
		}
		""";
}
