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

	@NotEmpty public List<String> canonicalObjects(@NotNull final HashInputConstants hashInputConstants) {
		return List.of(
			hashInputConstants.encode(this.saltBytes)
		);
	}

	public static void encode(@NotNull final HashInputConstants expectedHashInputConstants, @NotNull final HashInputVariables expectedHashInputVariables, @NotEmpty final List<String> hashInputsValues) {
		if (expectedHashInputConstants.encodeDecode().flags().encodeHashInputVariables()) {
			hashInputsValues.addAll(expectedHashInputVariables.canonicalObjects(expectedHashInputConstants));
		}
	}

	public static HashInputVariables decode(final HashInputVariables expectedHashInputVariables, final HashInputConstants expectedHashInputConstants, final List<String> hashInputPartsEncoded) {
		return expectedHashInputVariables.decode(hashInputPartsEncoded, expectedHashInputConstants);
	}

	private HashInputVariables decode(@NotEmpty final List<String> hashInputsEncoded, @NotNull final HashInputConstants hashInputConstants) {
		return new HashInputVariables(
			hashInputConstants.encodeDecode().flags().encodeHashInputVariables()
				? hashInputConstants.decode(hashInputsEncoded.removeFirst())
				: this.saltBytes
		);
	}
}
