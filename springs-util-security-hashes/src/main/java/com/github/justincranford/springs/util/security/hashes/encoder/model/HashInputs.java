package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.ArrayList;
import java.util.List;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public record HashInputs(
	@NotNull HashInputConstants hashInputConstants,
	@NotNull HashInputVariables hashInputVariables
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.hashInputVariables().canonicalBytes(), this.hashInputConstants().canonicalBytes());
	}

	public static String encode(final HashInputConstants hashInputConstants, final HashInputVariables hashInputVariables) {
		final List<String> hashInputsEncoded = new ArrayList<>();
		HashInputVariables.encode(hashInputConstants, hashInputVariables, hashInputsEncoded);
		HashInputConstants.encode(hashInputConstants, hashInputsEncoded);
		return StringUtil.toString("", hashInputConstants.encodeDecode().separator(), "", hashInputsEncoded);
	}

	public static HashInputs decode(@NotEmpty final String actualParametersEncoded, @NotNull final HashInputConstants expectedHashInputConstants, @NotNull final HashInputVariables expectedHashInputVariables) {
		final List<String>       hashInputsEncoded        = expectedHashInputConstants.splitInputs(actualParametersEncoded);
	    final HashInputVariables actualHashInputVariables = HashInputVariables.decode(expectedHashInputVariables, expectedHashInputConstants, hashInputsEncoded);
		final HashInputConstants actualHashInputConstants = HashInputConstants.decode(expectedHashInputConstants, hashInputsEncoded);
		if (!hashInputsEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		return new HashInputs(actualHashInputConstants, actualHashInputVariables);
	}
}
