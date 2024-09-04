package com.github.justincranford.springs.util.security.hashes.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;

@SuppressWarnings({"nls", "hiding"})
public class DigestAlgorithm {
    public enum ALG {
		MD2       ("MD2",         16, Oids.MD2),
		MD4       ("MD4",         16, Oids.MD4),
		MD5       ("MD5",         16, Oids.MD5),
		SHA1      ("SHA-1",       20, Oids.SHA1),
		SHA224    ("SHA-224",     28, Oids.SHA224),
		SHA256    ("SHA-256",     32, Oids.SHA256),
		SHA384    ("SHA-384",     48, Oids.SHA384),
		SHA512    ("SHA-512",     64, Oids.SHA512),
		SHA384_224("SHA-512/224", 48, Oids.SHA512_224),
		SHA512_256("SHA-512/255", 64, Oids.SHA512_256),
		SHA3_224  ("SHA3-224",    28, Oids.SHA3_224),
		SHA3_256  ("SHA3-256",    32, Oids.SHA3_256),
		SHA3_384  ("SHA3-384",    48, Oids.SHA3_384),
		SHA3_512  ("SHA3-512",    64, Oids.SHA3_512),
		SHAKE128  ("SHAKE128",    16, Oids.SHAKE128),
		SHAKE256  ("SHAKE256",    32, Oids.SHAKE256),
		;
		private final String value;
		private final int bytesLen;
		private final ASN1ObjectIdentifier oid;
		private final byte[] oidBytes;
		private ALG(final String value, final int bytesLen, final ASN1ObjectIdentifier oid0) {
			this.value    = value;
			this.bytesLen = bytesLen;
			this.oid      = oid0;
			this.oidBytes = Asn1Util.oidDerBytes(oid0);
		}
		public String value() {
			return this.value;
		}
		public int lengthBytes() {
			return this.bytesLen;
		}
		public ASN1ObjectIdentifier oid() {
			return this.oid;
		}
		public byte[] oidBytes() {
			return this.oidBytes;
		}
		public byte[] canonicalIdBytes() {
			return this.oidBytes;
		}

	    public byte[] compute(final byte[] bytes) {
			try {
				return MessageDigest.getInstance(this.value).digest(bytes);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		}

	    public byte[] compute(final byte[][] dataChunks) {
	        byte[] messageDigest = null;
	        for (final byte[] data : dataChunks) {
	            if (messageDigest == null) {
	                messageDigest = this.compute(data);
	            } else {
	                messageDigest = this.compute(ArrayUtil.concat(messageDigest, data));
	            }
	        }
	        return messageDigest;
	    }
	}

    public static class Oids {
		public static final ASN1ObjectIdentifier MD2        = new ASN1ObjectIdentifier("1.2.840.113549.2.2");
		public static final ASN1ObjectIdentifier MD4        = new ASN1ObjectIdentifier("1.2.840.113549.2.4");
		public static final ASN1ObjectIdentifier MD5        = new ASN1ObjectIdentifier("1.2.840.113549.2.5");
		public static final ASN1ObjectIdentifier SHA1       = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
		public static final ASN1ObjectIdentifier SHA224     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
		public static final ASN1ObjectIdentifier SHA256     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");
		public static final ASN1ObjectIdentifier SHA384     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.4");
		public static final ASN1ObjectIdentifier SHA512     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.5");
		public static final ASN1ObjectIdentifier SHA512_224 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.6");
		public static final ASN1ObjectIdentifier SHA512_256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.7");

		public static final ASN1ObjectIdentifier SHA3_224 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.8");
		public static final ASN1ObjectIdentifier SHA3_256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.9");
		public static final ASN1ObjectIdentifier SHA3_384 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.19");
		public static final ASN1ObjectIdentifier SHA3_512 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.11");

		public static final ASN1ObjectIdentifier SHAKE128 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.12");
		public static final ASN1ObjectIdentifier SHAKE256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.13");
    }
}
