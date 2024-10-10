package com.github.justincranford.springs.service.webauthn.register.data;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.yubico.webauthn.data.ByteArray;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class AttestationCertInfo {
	final ByteArray der;
	final String text;

	public AttestationCertInfo(ByteArray certDer) {
		this.der = certDer;
		X509Certificate cert = null;
		try (ByteArrayInputStream bais = new ByteArrayInputStream(certDer.getBytes())) {
			cert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(bais);
		} catch (CertificateException | IOException e) {
			log.error("Failed to parse attestation certificate", e);
		}
		if (cert == null) {
			this.text = null;
		} else {
			this.text = cert.toString();
		}
	}
}
