package com.github.justincranford.springs.util.security.hashes.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSequence;

@SuppressWarnings({"nls"})
public class Asn1Util {
	public static byte[] derBytes(final ASN1Object sequence) {
		try {
			return sequence.getEncoded("DER");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static DERSequence derSequence(final ASN1Encodable...asn1Encodables) {
		return new DERSequence(asn1Encodables);
	}
}
