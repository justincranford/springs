package com.github.justincranford.springs.util.security.hashes.encoder.pepper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.function.Function;

import com.github.justincranford.springs.util.security.hashes.encoder.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstants;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstantsAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputVariables;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputs;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputsAndHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Pepper;

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
			final byte[]             actualHashBytes          = computePepperedHash(rawInput, actualHashInputs, hashPeppers);
			return HashInputsAndHash.encodeHashInputsAndHash(actualHashInputs, actualHashBytes);
		};
		super.matches = (rawInput, actualHashInputsAndHashEncoded) -> {
			final HashInputVariables expectedHashInputVariables = new HashInputVariables(expectedSaltSupplier.apply(rawInput));
			final HashInputsAndHash  actualHashInputsAndHash    = HashInputsAndHash.decodeHashInputsAndHash(actualHashInputsAndHashEncoded, expectedHashInputConstants, expectedHashInputVariables);
			final HashInputs         actualHashInputs           = actualHashInputsAndHash.hashInputs();
			final byte[]             actualHashBytes            = actualHashInputsAndHash.hashBytes();
			final byte[]             expectedHashBytes          = computePepperedHash(rawInput, actualHashInputs, hashPeppers);
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
			final HashInputsAndHash  actualHashInputsAndHash    = HashInputsAndHash.decodeHashInputsAndHash(actualHashInputsAndHashEncoded, expectedHashInputConstants, expectedHashInputVariables);
			final HashInputs         actualHashInputs           = actualHashInputsAndHash.hashInputs();
			final HashInputConstants actualConstants            = actualHashInputs.hashInputConstants();
			final HashInputVariables actualVariables            = actualHashInputs.hashInputVariables();
			final int                actualSaltBytesLength      = actualVariables.saltBytes().length;
			final int                actualHashBytesLength      = Pepper.safeDecode(hashPeppers.postHash(), actualHashInputsAndHash.hashBytes()).length;
			return expectedHashInputConstants.recompute(expectedSaltBytesLength, actualSaltBytesLength, actualConstants, expectedHashBytesLength, actualHashBytesLength);
		};
	}

	private static byte[] computePepperedHash(final CharSequence rawInput, final HashInputs hashInputs, final HashPeppers hashPeppers) {
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
}
