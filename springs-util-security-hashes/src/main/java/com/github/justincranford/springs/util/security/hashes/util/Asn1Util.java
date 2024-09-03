package com.github.justincranford.springs.util.security.hashes.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

@SuppressWarnings({"nls"})
public class Asn1Util {
	public static byte[] oidDerBytes(final ASN1ObjectIdentifier oid) {
		try {
			return oid.getEncoded("DER");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
