package com.github.justincranford.springs.service.webauthn.register.util;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class ByteArrayUtil {
	public static ByteArray decodeBase64Url(final String idBase64Url) {
		try {
			return ByteArray.fromBase64Url(idBase64Url);
		} catch (Base64UrlException e) {
			log.info("Decode base64url exception", e);
			throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Decode base64url exception");
		}
	}

	public static ByteArray randomByteArray(final int numBytes) {
		return new ByteArray(SecureRandomUtil.randomBytes(numBytes));
	}
}

