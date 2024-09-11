package com.github.justincranford.springs.util.security.hashes.encoder.model;

import javax.crypto.SecretKey;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public interface Pepper {
	@Null SecretKey secretKey();				// high-entropy 256-bit random key; n.b. may be null
	@Null DigestAlgorithm secretKeyDigest();	// if secretKey omitted, required to derive secretKeyBytes from inputs
	@NotNull byte[] secretContext();			// may be empty (e.g. any-entropy N-byte value)
	@NotNull byte[] clearContext();				// may be empty (e.g. "application1".getBytes(), "feature1".getBytes(), any-entropy N-byte value)
	@NotNull  MacAlgorithm mac();				// required (e.g. HmacSHA256, CMAC256); used as Mac digest, as well as for deriving low-entropy hmacKey if secretKey=null
	@NotNull  Base64Util.EncoderDecoder encoderDecoder(); // required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
	@NotNull public byte[] compute(@NotEmpty final byte[] rawInput, @NotNull final byte[] additionalData);
}
