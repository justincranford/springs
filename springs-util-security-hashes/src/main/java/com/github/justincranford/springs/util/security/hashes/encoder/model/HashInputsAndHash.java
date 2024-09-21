package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public record HashInputsAndHash(
	@NotNull HashInputs hashInputs,
	@NotNull Hash       hash
) {
	public static String encodeHashInputsAndHash(
		@NotNull final HashInputs hashInputs,
		@NotNull final Hash       hash
	) {
		final String actualHashInputsEncoded = HashInputs.encode(hashInputs.hashInputConstants(), hashInputs.hashInputVariables());
		final String actualHashEncoded       = Hash.encode(hashInputs.hashInputConstants(), hash);
		if (actualHashInputsEncoded.isEmpty()) {
			return actualHashEncoded;
		}
		return actualHashInputsEncoded + hashInputs.hashInputConstants().codec().outerSeparator() + actualHashEncoded;
	}

	public static HashInputsAndHash decodeHashInputsAndHash(
		@NotNull final String             actualHashInputsAndHashEncoded,
		@NotNull final HashInputConstants expectedHashInputConstants,
		@NotNull final HashInputVariables expectedHashInputVariables
	) {
	    final List<String> actualInputsAndHashEncoded = StringUtil.split(actualHashInputsAndHashEncoded, expectedHashInputConstants.codec().outerSeparator());
	    if ((actualInputsAndHashEncoded.size() != 1) && (actualInputsAndHashEncoded.size() != 2)) {
			throw new RuntimeException("Incorrect size");
	    }
		final String       actualInputsEncoded        = (actualInputsAndHashEncoded.size() == 1) ? "" : actualInputsAndHashEncoded.removeFirst();
		final String       actualHashEncoded          = actualInputsAndHashEncoded.removeFirst();
		if (!actualInputsAndHashEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		final HashInputs actualHashInputs = HashInputs.decode(actualInputsEncoded, expectedHashInputConstants, expectedHashInputVariables);
		final Hash       actualHash       = Hash.decode(expectedHashInputConstants, actualHashEncoded);
		return new HashInputsAndHash(actualHashInputs, actualHash);
	}
}
