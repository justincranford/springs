package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import javax.crypto.SecretKey;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public record Pepper(
	@Null SecretKey secretKey,				// high-entropy 256-bit random key; n.b. may be null
	@Null DigestAlgorithm secretKeyDigest,	// if secretKey omitted, required to derive secretKeyBytes from inputs
	@NotNull byte[] secretContext,			// may be empty (e.g. any-entropy N-byte value)
	@NotNull byte[] clearContext,			// may be empty (e.g. "application1".getBytes(), "feature1".getBytes(), any-entropy N-byte value)
	@NotNull  MacAlgorithm mac,				// required (e.g. HmacSHA256, CMAC256); used as Mac digest, as well as for deriving low-entropy hmacKey if secretKey=null
	@NotNull  Base64Util.EncoderDecoder encoderDecoder // required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
) implements PepperInterface {
	public static byte[] safeComputeAndEncode(@Null final PepperInterface pepper, @NotEmpty final byte[] rawInput, @NotNull final byte[] additionalData) {
		if (pepper == null) {
			return rawInput;
		}
		// Assumption: Mac algorithm will Mac chain all of the inputs
		final byte[][] dataChunks = List.of(
			rawInput,				// Priority 1: required, unique input (e.g. deterministic hashing of PII)
			pepper.secretContext(),	// Priority 2: optional, secret entropy; useful if secretKey=null (or reused)
			additionalData,			// Priority 3: optional, data binding (e.g. Pbkdf2 => salt+iter+dkLen, Argon2 => salt+lanes+mem, AES/GCM => IV+AAD)
			pepper.clearContext()	// Priority 4: optional, clear entropy; useful if secretKey=null (or reused) and secretContext=null (or reused)
		).toArray(new byte[0][]);

		// Use high-entropy secretKey (i.e. optimal), or low-entropy concatData-derived secretKey (i.e. fallback)
		final SecretKey macKey = (pepper.secretKey() != null) ? pepper.secretKey() : pepper.mac().secretKeyFromDataChunks(dataChunks);

		final byte[] pepperMac = pepper.mac().chain(macKey, dataChunks);
		return pepper.encoderDecoder().encodeToBytes(pepperMac);	// required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
	}

	public static int safeLength(@Null final PepperInterface pepper, @Min(1) final int defaultLen) {
		return (pepper != null) ? pepper.mac().outputBytesLen() : defaultLen;
	}

	public static byte[] safeDecode(@Null final PepperInterface pepper, @Min(1) final byte[] bytes) {
		return (pepper != null) ? pepper.encoderDecoder().decodeFromBytes(bytes) : bytes;
	}
}
