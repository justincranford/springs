package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import com.github.justincranford.springs.util.security.hashes.encoder.IocEncoder;

import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public abstract class PepperedHashEncoderV1 extends IocEncoder {
	public PepperedHashEncoderV1(
		@NotNull final HashInputConstantsAndHashPeppers expectedHashInputConstantsAndHashPeppers,
		@NotNull final Function<CharSequence, byte[]>   expectedHashInputVariablesBytesSupplier
	) {
		final HashInputConstants expectedHashInputConstants = expectedHashInputConstantsAndHashPeppers.hashInputConstants();
		final HashPeppers        hashPeppers                = expectedHashInputConstantsAndHashPeppers.hashPeppers();
		super.encode = (rawInput) -> {
			final HashInputVariables actualHashInputVariables = new HashInputVariables(expectedHashInputVariablesBytesSupplier.apply(rawInput));
			final HashInputs         actualHashInputs         = new HashInputs(expectedHashInputConstants, actualHashInputVariables);
			final Hash               actualHash               = computePepperedHash(rawInput, actualHashInputs, hashPeppers);
			return HashInputsAndHash.encodeHashInputsAndHash(actualHashInputs, actualHash);
		};
		super.matches = (rawInput, actualHashInputsAndHashEncoded) -> {
			final HashInputVariables expectedHashInputVariables = new HashInputVariables(expectedHashInputVariablesBytesSupplier.apply(rawInput));
			final HashInputsAndHash  actualHashInputsAndHash    = HashInputsAndHash.decodeHashInputsAndHash(actualHashInputsAndHashEncoded, expectedHashInputConstants, expectedHashInputVariables);
			final HashInputs         actualHashInputs           = actualHashInputsAndHash.hashInputs();
			final Hash               actualHash                 = actualHashInputsAndHash.hash();
			final Hash               expectedHash               = computePepperedHash(rawInput, actualHashInputs, hashPeppers);
			return Hash.isEqual(actualHash, expectedHash);
		};
		super.upgradeEncoding = (actualHashInputsAndHashEncoded) -> {
			if (actualHashInputsAndHashEncoded == null || actualHashInputsAndHashEncoded.length() == 0) {
				return Boolean.FALSE;
			}
			final CharSequence       expectedRawInput                      = "";
			final int                expectedHashInputVariablesBytesLength = Pepper.safeLength(hashPeppers.inputVariables(), expectedHashInputVariablesBytesSupplier.apply(expectedRawInput).length);
			final int                expectedHashBytesLength               = Pepper.safeLength(hashPeppers.postHash(), expectedRawInput.length());
			final HashInputVariables expectedHashInputVariables            = new HashInputVariables(new byte[expectedHashInputVariablesBytesLength]);
			final HashInputsAndHash  actualHashInputsAndHash               = HashInputsAndHash.decodeHashInputsAndHash(actualHashInputsAndHashEncoded, expectedHashInputConstants, expectedHashInputVariables);
			final HashInputs         actualHashInputs                      = actualHashInputsAndHash.hashInputs();
			final Hash               actualHash                            = actualHashInputsAndHash.hash();
			final HashInputConstants actualConstants                       = actualHashInputs.hashInputConstants();
			final HashInputVariables actualVariables                       = actualHashInputs.hashInputVariables();
			final int                actualHashInputVariablesBytesLength   = actualVariables.hashInputVariablesBytes().length;
			final int                actualHashBytesLength                 = Pepper.safeDecode(hashPeppers.postHash(), actualHash.hashBytes()).length;
			return expectedHashInputConstants.recompute(expectedHashInputVariablesBytesLength, actualHashInputVariablesBytesLength, actualConstants, expectedHashBytesLength, actualHashBytesLength);
		};
	}

	private static Hash computePepperedHash(final CharSequence rawInput, final HashInputs hashInputs, final HashPeppers hashPeppers) {
		final HashInputConstants hashInputConstants              = hashInputs.hashInputConstants();
		final byte[]             plainHashInputVariablesBytes    = hashInputs.hashInputVariables().hashInputVariablesBytes();
		final byte[]             additionalDataBytes             = hashInputs.canonicalBytes();
		final byte[]             pepperedHashInputVariablesBytes = Pepper.safeComputeAndEncode(hashPeppers.inputVariables(), plainHashInputVariablesBytes, additionalDataBytes);
		final byte[]             plainInputBytes                 = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]             pepperedInputBytes              = Pepper.safeComputeAndEncode(hashPeppers.preHash(), plainInputBytes, additionalDataBytes);
		final String             pepperedInputString             = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]             plainHashBytes                  = hashInputConstants.compute(pepperedHashInputVariablesBytes, pepperedInputString);
		final byte[]             pepperedHashBytes               = Pepper.safeComputeAndEncode(hashPeppers.postHash(), plainHashBytes, additionalDataBytes);
		return new Hash(pepperedHashBytes);
	}
}
