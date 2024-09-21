package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.HashCodec;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

// TODO abstract instead of interface (codec, hashBytesLen)
public interface HashInputConstants {
	@NotNull public HashAlgorithm algorithm();
	@NotNull HashCodec codec();
	@Min(CommonConstraints.MIN_HASH_BYTES_LEN) int hashBytesLen();
	@NotNull public byte[] canonicalBytes();
	@NotEmpty public List<String> canonicalObjects();
	@NotNull public byte[] compute(@NotNull final byte[] variableInputConstantsBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean recompute( // TODO abstract
		@Min(CommonConstraints.MIN_HASH_INPUT_VARIABLES_BYTES_LEN) final int                expectedHashInputVariablesBytesLength,
		@Min(CommonConstraints.MIN_HASH_INPUT_VARIABLES_BYTES_LEN) final int                actualHashInputVariablesBytesLength,
		@NotNull                                                   final HashInputConstants actualHashInputConstants,
		@Min(CommonConstraints.MIN_HASH_BYTES_LEN)                 final int                expectedHashBytesLength,
		@Min(CommonConstraints.MIN_HASH_BYTES_LEN)                 final int                actualHashBytesLength
	);
	@NotEmpty public HashInputConstants decode(@NotEmpty List<String> parts);

	default public List<String> splitInputs(@NotNull final String hashInputsEncoded) {
		return StringUtil.split(hashInputsEncoded, this.codec().innerSeparator());
	}

	default public String encode(@NotEmpty final byte[] plain) {
		return this.codec().codec().encodeToString(plain);
	}
	default public byte[] decode(@NotEmpty final String encoded) {
		return this.codec().codec().decodeFromString(encoded);
	}

	public static void appendEncodeInput(@NotNull final HashInputConstants expectedHashInputConstants, @NotEmpty final List<String> hashInputsValues) {
		if (expectedHashInputConstants.codec().flags().encodeHashInputConstants()) {
			hashInputsValues.addAll(expectedHashInputConstants.canonicalObjects());
		}
	}

	public static HashInputConstants decode(final HashInputConstants expectedHashInputConstants, final List<String> hashInputPartsEncoded) {
		return expectedHashInputConstants.decode(hashInputPartsEncoded);
	}

	public static class CommonConstraints {
		public static final int MIN_HASH_INPUT_VARIABLES_BYTES_LEN = 0;	// Absolute Min (Testing): 0-bit,  Recommended Min (Production): 256-bit/32-bytes
		public static final int MIN_HASH_BYTES_LEN = 8;	// Absolute Min (Testing): 64-bit, Recommended Min (Production): 256-bit/32-bytes
	}
}
