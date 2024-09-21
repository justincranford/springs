package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record HashInputVariables(
	@NotEmpty byte[] hashInputVariablesBytes // Hmac salt or AEAD IV (aka nonce)
) {
	public byte[] canonicalBytes() {
		return this.hashInputVariablesBytes;
	}

	@NotEmpty public List<String> canonicalObjects(@NotNull final HashInputConstants hashInputConstants) {
		return List.of(
			hashInputConstants.encode(this.hashInputVariablesBytes)
		);
	}

	public static void appendEncodeInput(@NotNull final HashInputConstants expectedHashInputConstants, @NotNull final HashInputVariables expectedHashInputVariables, @NotEmpty final List<String> hashInputsValues) {
		if (expectedHashInputConstants.codec().flags().encodeHashInputVariables()) {
			hashInputsValues.addAll(expectedHashInputVariables.canonicalObjects(expectedHashInputConstants));
		}
	}

	public static HashInputVariables decode(final HashInputVariables expectedHashInputVariables, final HashInputConstants expectedHashInputConstants, final List<String> hashInputPartsEncoded) {
		return expectedHashInputVariables.decode(hashInputPartsEncoded, expectedHashInputConstants);
	}

	private HashInputVariables decode(@NotEmpty final List<String> hashInputsEncoded, @NotNull final HashInputConstants hashInputConstants) {
		return new HashInputVariables(
			hashInputConstants.codec().flags().encodeHashInputVariables()
				? hashInputConstants.decode(hashInputsEncoded.removeFirst())
				: this.hashInputVariablesBytes
		);
	}
}
