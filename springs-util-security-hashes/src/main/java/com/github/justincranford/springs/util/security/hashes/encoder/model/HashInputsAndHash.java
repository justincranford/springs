package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public record HashInputsAndHash(
	@NotNull HashInputs hashInputs,
	@NotNull byte[] hashBytes
) {
	public static String encodeHashInputsAndHash(@NotNull final HashInputs hashInputs, @NotEmpty final byte[] actualHashBytes) {
		final String actualHashInputsEncoded = HashInputs.encodeHashInputs(hashInputs.hashInputConstants(), hashInputs.hashInputVariables());
		final String actualHashEncoded       = HashInputsAndHash.encodeHash(hashInputs, actualHashBytes);
		if (actualHashInputsEncoded.isEmpty()) {
			return actualHashEncoded;
		}
		return actualHashInputsEncoded + hashInputs.hashInputConstants().encodeDecode().separators().parametersVsHash() + actualHashEncoded;
	}

	private static String encodeHash(final HashInputs hashInputs, final byte[] actualHashBytes) {
		return hashInputs.hashInputConstants().encode(actualHashBytes);
	}

	public static HashInputsAndHash decodeHashInputsAndHash(@NotNull final String actualHashInputsAndHashEncoded, @NotNull final HashInputConstants expectedHashInputConstants, @NotNull final HashInputVariables expectedHashInputVariables) {
	    final List<String> actualInputsAndHashEncoded = HashInputsAndHash.splitInputsVsHash(expectedHashInputConstants, actualHashInputsAndHashEncoded);
		final String       actualInputsEncoded        = (actualInputsAndHashEncoded.size() == 1) ? "" : actualInputsAndHashEncoded.removeFirst();
		final String       actualHashEncoded          = actualInputsAndHashEncoded.removeFirst();
		if (!actualInputsAndHashEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		final HashInputs actualHashInputs = HashInputs.decodeHashInputs(actualInputsEncoded, expectedHashInputConstants, expectedHashInputVariables);
		final byte[]     actualHashBytes  = expectedHashInputConstants.decode(actualHashEncoded);
		return new HashInputsAndHash(actualHashInputs, actualHashBytes);
	}

	private static List<String> splitInputsVsHash(@NotNull final HashInputConstants hashInputConstants, final String hashInputsAndHashEncoded) {
		return StringUtil.split(hashInputsAndHashEncoded, hashInputConstants.encodeDecode().separators().parametersVsHash());
	}

}
