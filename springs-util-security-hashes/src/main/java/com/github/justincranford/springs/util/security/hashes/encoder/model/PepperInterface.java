package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import javax.crypto.SecretKey;

import com.github.justincranford.springs.util.basic.TextCodec;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public interface PepperInterface {
	@NotNull  MacAlgorithm mac();				// required (e.g. HmacSHA256, CMAC256); used as Mac digest, as well as for deriving low-entropy hmacKey if secretKey=null
	@NotNull  TextCodec codec(); 				// required (e.g. mitigate bcrypt truncation weaknesses w.r.t null bytes and max 72-bytes)
	@Null SecretKey secretKey();				// high-entropy 256-bit random key; n.b. may be null
	@Null DigestAlgorithm secretKeyDigest();	// if secretKey omitted, required to derive secretKeyBytes from inputs
	@NotNull byte[] secretContext();			// may be empty (e.g. any-entropy N-byte value)
	@NotNull byte[] clearContext();				// may be empty (e.g. "application1".getBytes(), "feature1".getBytes(), any-entropy N-byte value)

	public static byte[] safeComputeAndEncode(@Null PepperInterface pepperInterface, @NotEmpty final byte[] rawInput, @NotNull final byte[] additionalData) {
		if (pepperInterface == null) {
			return rawInput;
		}

		final byte[][] dataChunks = List.of(
			rawInput,							// mitigate input reuse (e.g. prf salt, cipher IV)
			pepperInterface.secretContext(),	// secret entropy; useful if secretKey=null (or reused)
			additionalData,						// data binding (e.g. Pbkdf2 => salt+iter+dkLen, Argon2 => salt+lanes+mem, AES/GCM => IV+AAD)
			pepperInterface.clearContext()		// clear entropy; useful if secretKey=null (or reused) and secretContext=null (or reused)
		).toArray(new byte[0][]);

		// Use high-entropy secretKey (i.e. optimal), or low-entropy concatData-derived secretKey (i.e. fallback)
		final SecretKey macKey = (pepperInterface.secretKey() != null) ? pepperInterface.secretKey() : pepperInterface.mac().secretKeyFromDataChunks(pepperInterface.secretKeyDigest(), dataChunks);

		final byte[] pepperMac = pepperInterface.mac().chain(macKey, dataChunks);

		// Priority: required, mitigate hash weaknesses (e.g. bcrypt truncation, due to null bytes or max 72-bytes)
		return pepperInterface.codec().encodeToBytes(pepperMac);
	}
}
