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
		final String actualHashEncoded       = Hash.encode(hash.hashBytes(), hash.hashConstants());
		if (actualHashInputsEncoded.isEmpty()) {
			return actualHashEncoded;
		}
		return actualHashInputsEncoded + hash.hashConstants().separator() + actualHashEncoded;
	}

	public static HashInputsAndHash decodeHashInputsAndHash(
		@NotNull final String             actualHashInputsAndHashEncoded,
		@NotNull final HashConstants      expectedHashConstants,
		@NotNull final HashInputConstants expectedHashInputConstants,
		@NotNull final HashInputVariables expectedHashInputVariables
	) {
	    final List<String> actualInputsAndHashEncoded = StringUtil.split(actualHashInputsAndHashEncoded, expectedHashConstants.separator());
		final String       actualInputsEncoded        = (actualInputsAndHashEncoded.size() == 1) ? "" : actualInputsAndHashEncoded.removeFirst();
		final String       actualHashEncoded          = actualInputsAndHashEncoded.removeFirst();
		if (!actualInputsAndHashEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		final HashInputs actualHashInputs = HashInputs.decode(actualInputsEncoded, expectedHashInputConstants, expectedHashInputVariables);
		final Hash       actualHash       = Hash.decode(actualHashEncoded, expectedHashConstants);
		return new HashInputsAndHash(actualHashInputs, actualHash);
	}
}
