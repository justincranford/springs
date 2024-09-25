package com.github.justincranford.springs.util.security.hashes.encoder.model;

import javax.crypto.SecretKey;

import com.github.justincranford.springs.util.basic.TextCodec;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public record Pepper(
	@NotNull  MacAlgorithm mac,				// required (e.g. HmacSHA256, CMAC256); used as Mac digest, as well as for deriving low-entropy hmacKey if secretKey=null
	@NotNull  TextCodec codec, 				// required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
	@Null SecretKey secretKey,				// high-entropy 256-bit random key; n.b. may be null
	@Null DigestAlgorithm secretKeyDigest,	// if secretKey omitted, required to derive secretKeyBytes from inputs
	@NotNull byte[] secretContext,			// may be empty (e.g. any-entropy N-byte value)
	@NotNull byte[] clearContext			// may be empty (e.g. "application1".getBytes(), "feature1".getBytes(), any-entropy N-byte value)
) implements PepperInterface {
	public static int safeLength(@Null final PepperInterface pepper, @Min(1) final int defaultLen) {
		return (pepper != null) ? pepper.mac().outputBytesLen() : defaultLen;
	}

	public static byte[] safeDecode(@Null final PepperInterface pepper, @Min(1) final byte[] bytes) {
		return (pepper != null) ? pepper.codec().decodeFromBytes(bytes) : bytes;
	}
}
