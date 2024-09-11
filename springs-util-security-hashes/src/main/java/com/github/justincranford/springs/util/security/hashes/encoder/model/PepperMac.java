package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import javax.crypto.SecretKey;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public record PepperMac(
	@Null SecretKey secretKey,				// high-entropy 256-bit random key; n.b. may be null
	@Null DigestAlgorithm secretKeyDigest,	// if secretKey omitted, required to derive secretKeyBytes from inputs
	@NotNull byte[] secretContext,			// may be empty (e.g. any-entropy N-byte value)
	@NotNull byte[] clearContext,			// may be empty (e.g. "application1".getBytes(), "feature1".getBytes(), any-entropy N-byte value)
	@NotNull  MacAlgorithm mac,				// required (e.g. HmacSHA256, CMAC256); used as Mac digest, as well as for deriving low-entropy hmacKey if secretKey=null
	@NotNull  Base64Util.EncoderDecoder encoderDecoder // required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
) implements Pepper {
	@Override
	public byte[] compute(@NotEmpty final byte[] rawInput, @NotNull final byte[] additionalData) {
		// Assumption: Mac algorithm will Mac chain all of the inputs
		final byte[][] dataChunks = List.of(
			rawInput,								// Priority 1: required, unique input (e.g. deterministic hashing of PII)
			additionalData,							// Priority 2: optional, data binding (e.g. Pbkdf2 => salt+iter+dkLen, Argon2 => salt+lanes+mem)
			this.secretContext,						// Priority 3: optional, secret entropy; useful if secretKey=null (or reused)
			this.clearContext						// Priority 4: optional, clear entropy; useful if secretKey=null (or reused) and secretContext=null (or reused)
//			this.mac.asn1OidBytes() 				// Priority 5: required, Mac canonical algorithm identifier
//			this.encoderDecoder.canonicalEncode()	// Priority 6: optional, text encoder algorithm identifier 
		).toArray(new byte[0][]);

		// Use high-entropy secretKey (i.e. optimal), or low-entropy concatData-derived secretKey (i.e. fallback)
		final SecretKey macKey = (this.secretKey != null) ? this.secretKey : this.mac.secretKeyFromDataChunks(this.secretKeyDigest, dataChunks);

		final byte[] pepperMac = this.mac.chain(macKey, dataChunks);
		return this.encoderDecoder.encodeToBytes(pepperMac);	// required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
	}
}
