package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record HashInputVariables(
	@NotEmpty byte[] saltBytes
) {
	public byte[] canonicalBytes() {
		return this.saltBytes;
	}


	@NotEmpty public List<Object> canonicalObjects(@NotNull final HashInputConstants hashInputConstants) {
		return List.of(
			hashInputConstants.encodeDecode().encoderDecoder().encodeToString(this.saltBytes)
		);
	}

	public HashInputVariables decode(@NotEmpty final List<String> hashInputsEncoded, @NotNull final HashInputConstants hashInputConstants) {
		final byte[] expectedSaltBytes = this.saltBytes;
		final byte[] actualSaltBytes   = (hashInputConstants.encodeDecode().flags().encodeHashInputVariables()) ? hashInputConstants.encodeDecode().encoderDecoder().decodeFromString(hashInputsEncoded.removeFirst()) : expectedSaltBytes;
		return new HashInputVariables(actualSaltBytes);
	}

	public String encode(@NotNull final HashInputConstants hashInputConstants, @NotEmpty final byte[] plain) {
		return hashInputConstants.encodeDecode().encoderDecoder().encodeToString(plain);
	}
	public byte[] decode(@NotNull final HashInputConstants hashInputConstants, @NotEmpty final String encoded) {
		return hashInputConstants.encodeDecode().encoderDecoder().decodeFromString(encoded);
	}
}
