package com.github.justincranford.springs.util.security.hashes.encoder.pepper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstants;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstantsAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputs;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputsAndHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputVariables;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Pepper;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public abstract class PepperedHashEncoderV1 extends IocEncoder {
	public PepperedHashEncoderV1(
		@NotNull final HashInputConstantsAndHashPeppers expectedHashInputConstantsAndHashPeppers,
		@NotNull final Function<CharSequence, byte[]>   expectedSaltSupplier
	) {
		final HashInputConstants expectedHashInputConstants = expectedHashInputConstantsAndHashPeppers.hashInputConstants();
		final HashPeppers        hashPeppers                = expectedHashInputConstantsAndHashPeppers.hashPeppers();
		super.encode = (rawInput) -> {
			final HashInputVariables actualHashInputVariables = new HashInputVariables(expectedSaltSupplier.apply(rawInput));
			final HashInputs         actualHashInputs         = new HashInputs(expectedHashInputConstants, actualHashInputVariables);
			final byte[]             actualHashBytes          = computeHash(rawInput, actualHashInputs, hashPeppers);
			return actualHashInputs.encodeHashInputsAndHash(actualHashBytes);
		};
		super.matches = (rawInput, actualHashInputsAndHashEncoded) -> {
			final HashInputVariables expectedHashInputVariables = new HashInputVariables(expectedSaltSupplier.apply(rawInput));
			final HashInputsAndHash  actualHashInputsAndHash    = decodeHashInputsAndHash(actualHashInputsAndHashEncoded, expectedHashInputConstants, expectedHashInputVariables);
			final HashInputs         actualHashInputs           = actualHashInputsAndHash.hashInputs();
			final byte[]             actualHashBytes            = actualHashInputsAndHash.hashBytes();
			final byte[]             expectedHashBytes          = computeHash(rawInput, actualHashInputs, hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(expectedHashBytes, actualHashBytes));
		};
		super.upgradeEncoding = (actualHashInputsAndHashEncoded) -> {
			if (actualHashInputsAndHashEncoded == null || actualHashInputsAndHashEncoded.length() == 0) {
				return Boolean.FALSE;
			}
			final CharSequence       expectedRawInput           = "";
			final int                expectedSaltBytesLength    = Pepper.safeLength(hashPeppers.salt(), expectedSaltSupplier.apply(expectedRawInput).length);
			final int                expectedHashBytesLength    = Pepper.safeLength(hashPeppers.postHash(), expectedRawInput.length());
			final HashInputVariables expectedHashInputVariables = new HashInputVariables(new byte[expectedSaltBytesLength]);
			final HashInputsAndHash  actualHashInputsAndHash    = decodeHashInputsAndHash(actualHashInputsAndHashEncoded, expectedHashInputConstants, expectedHashInputVariables);
			final HashInputs         actualHashInputs           = actualHashInputsAndHash.hashInputs();
			final HashInputConstants actualConstants            = actualHashInputs.hashInputConstants();
			final HashInputVariables actualVariables            = actualHashInputs.hashInputVariables();
			final int                actualSaltBytesLength      = actualVariables.saltBytes().length;
			final int                actualHashBytesLength      = Pepper.safeDecode(hashPeppers.postHash(), actualHashInputsAndHash.hashBytes()).length;
			return expectedHashInputConstants.recompute(expectedSaltBytesLength, actualSaltBytesLength, actualConstants, expectedHashBytesLength, actualHashBytesLength);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashInputs hashInputs, final HashPeppers hashPeppers) {
		final HashInputConstants hashInputConstants  = hashInputs.hashInputConstants();
		final byte[]             plainSaltBytes      = hashInputs.hashInputVariables().saltBytes();
		final byte[]             additionalDataBytes = hashInputs.canonicalBytes();
		final byte[]             pepperedSaltBytes   = Pepper.safeComputeAndEncode(hashPeppers.salt(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]             plainInputBytes     = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]             pepperedInputBytes  = Pepper.safeComputeAndEncode(hashPeppers.preHash(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String             pepperedInputString = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]             plainHashBytes      = hashInputConstants.compute(pepperedSaltBytes, pepperedInputString);
		final byte[]             pepperedHashBytes   = Pepper.safeComputeAndEncode(hashPeppers.postHash(), plainHashBytes, additionalDataBytes); // post-hash step
		return pepperedHashBytes;
	}

	public HashInputsAndHash decodeHashInputsAndHash(@NotNull final String actualHashInputsAndHashEncoded, @NotNull final HashInputConstants expectedHashInputConstants, @NotNull final HashInputVariables expectedHashInputVariables) {
	    final List<String> actualInputsAndHashEncoded = expectedHashInputConstants.splitInputsVsHash(actualHashInputsAndHashEncoded);
		final String       actualInputsEncoded        = (actualInputsAndHashEncoded.size() == 1) ? "" : actualInputsAndHashEncoded.removeFirst();
		final String       actualHashEncoded          = actualInputsAndHashEncoded.removeFirst();
		if (!actualInputsAndHashEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		final HashInputs actualHashInputs = decodeHashInputs(actualInputsEncoded, expectedHashInputConstants, expectedHashInputVariables);
		final byte[]     actualHashBytes  = expectedHashInputConstants.decode(actualHashEncoded);
		return new HashInputsAndHash(actualHashInputs, actualHashBytes);
	}

	private HashInputs decodeHashInputs(@NotEmpty final String actualParametersEncoded, @NotNull final HashInputConstants expectedHashInputConstants, @NotNull final HashInputVariables expectedHashInputVariables) {
		final List<String>       hashInputPartsEncoded    = expectedHashInputConstants.splitInputs(actualParametersEncoded);
	    final HashInputVariables actualHashInputVariables = expectedHashInputVariables.decode(hashInputPartsEncoded, expectedHashInputConstants);
		final HashInputConstants actualHashInputConstants = expectedHashInputConstants.decode(hashInputPartsEncoded);
		if (!hashInputPartsEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		return new HashInputs(actualHashInputConstants, actualHashInputVariables);
	}
}
