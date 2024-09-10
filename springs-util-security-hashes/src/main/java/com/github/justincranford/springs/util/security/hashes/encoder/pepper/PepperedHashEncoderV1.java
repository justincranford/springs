package com.github.justincranford.springs.util.security.hashes.encoder.pepper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParametersAndHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashVariableParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Pepper;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public abstract class PepperedHashEncoderV1 extends IocEncoder {
	public PepperedHashEncoderV1(
		@NotNull final HashConstantParametersAndHashPeppers expectedHashConstantParametersAndHashPeppers,
		@NotNull final Function<CharSequence, byte[]>       expectedSaltSupplier
	) {
		final HashConstantParameters expectedHashConstantParameters = expectedHashConstantParametersAndHashPeppers.hashConstantParameters();
		final HashPeppers            hashPeppers                    = expectedHashConstantParametersAndHashPeppers.hashPeppers();
		super.encode = (rawInput) -> {
			final HashVariableParameters actualHashVariableParameters = new HashVariableParameters(expectedSaltSupplier.apply(rawInput));
			final HashParameters         actualHashParameters         = new HashParameters(expectedHashConstantParameters, actualHashVariableParameters);
			final byte[]                 actualHashBytes              = computeHash(rawInput, actualHashParameters, hashPeppers);
			return encodeHashParametersAndHash(actualHashParameters, actualHashBytes);
		};
		super.matches = (rawInput, actualHashParametersAndHashEncoded) -> {
			final HashVariableParameters expectedHashVariableParameters = new HashVariableParameters(expectedSaltSupplier.apply(rawInput));
			final HashParametersAndHash  actualHashParametersAndHash    = decodeHashParametersAndHash(actualHashParametersAndHashEncoded, expectedHashConstantParameters, expectedHashVariableParameters);
			final HashParameters         actualHashParameters           = actualHashParametersAndHash.hashParameters();
			final byte[]                 actualHashBytes                = computeHash(rawInput, actualHashParameters, hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(actualHashBytes, actualHashParametersAndHash.hashBytes()));
		};
		super.upgradeEncoding = (actualHashParametersAndHashEncoded) -> {
			if (actualHashParametersAndHashEncoded == null || actualHashParametersAndHashEncoded.length() == 0) {
				return Boolean.FALSE;
			}
			final int                    expectedSaltBytesLength        = hashPeppers.hashSaltPepper().pepper().outputBytesLength(expectedSaltSupplier.apply("").length);
			final int                    expectedHashBytesLength        = hashPeppers.hashPostHashPepper().pepper().outputBytesLength(expectedSaltSupplier.apply("").length);
			final HashVariableParameters expectedHashVariableParameters = new HashVariableParameters(new byte[expectedSaltBytesLength]);
			final HashParametersAndHash  actualHashParametersAndHash    = decodeHashParametersAndHash(actualHashParametersAndHashEncoded, expectedHashConstantParameters, expectedHashVariableParameters);
			final HashParameters         actualHashParameters           = actualHashParametersAndHash.hashParameters();
			final HashConstantParameters actualConstantParameters       = actualHashParameters.hashConstantParameters();
			final HashVariableParameters actualVariableParameters       = actualHashParameters.hashVariableParameters();
			final int                    actualSaltBytesLength          = actualVariableParameters.hashSaltBytes().length;
			final int                    actualHashBytesLength          = optionalDecodePepper(hashPeppers.hashPostHashPepper().pepper(), actualHashParametersAndHash.hashBytes()).length;
			return expectedHashConstantParameters.recompute(expectedSaltBytesLength, actualSaltBytesLength, actualConstantParameters, expectedHashBytesLength, actualHashBytesLength);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashParameters hashParameters, final HashPeppers peppersForHash) {
		final HashConstantParameters hashConstantParameters = hashParameters.hashConstantParameters();
		final byte[]                 plainSaltBytes         = hashParameters.hashVariableParameters().hashSaltBytes();
		final byte[]                 additionalDataBytes    = hashParameters.canonicalBytes();
		final byte[]                 pepperedSaltBytes      = optionalPepperAndEncode(peppersForHash.hashSaltPepper().pepper(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]                 plainInputBytes        = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]                 pepperedInputBytes     = optionalPepperAndEncode(peppersForHash.hashPreHashPepper().pepper(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String                 pepperedInputString    = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]                 plainHashBytes         = computeHash(hashConstantParameters, pepperedSaltBytes, pepperedInputString);
		final byte[]                 pepperedHashBytes      = optionalPepperAndEncode(peppersForHash.hashPostHashPepper().pepper(), plainHashBytes, additionalDataBytes); // post-hash step (aka pepper)
		return pepperedHashBytes;
	}

	private static byte[] optionalPepperAndEncode(@Null final Pepper pepper, @NotEmpty final byte[] bytes, @NotNull final byte[] additionalData) {
		return (pepper == null) ? bytes : pepper.compute(bytes, additionalData);
	}
	private static byte[] optionalDecodePepper(@Null final Pepper pepper, @NotNull final byte[] bytes) {
		return (pepper == null) ? bytes : pepper.encoderDecoder().decodeFromBytes(bytes);
	}

	private static byte[] computeHash(@NotNull final HashConstantParameters hashConstantParameters, @NotNull final byte[] hashSaltBytes, @NotNull final CharSequence rawInput) {
		return hashConstantParameters.compute(hashSaltBytes, rawInput);
	}

	private static String encodeHashParametersAndHash(@NotNull final HashParameters hashParameters, @NotEmpty final byte[] hashBytes) {
		final String encodedHashParameters = encodeHashParameters(hashParameters);
		final String encodedHash           = encodeHash(hashParameters.hashConstantParameters(), hashBytes);
		if (encodedHashParameters.isEmpty()) {
			return encodedHash;
		}
		return encodedHashParameters + hashParameters.hashConstantParameters().encodeDecode().separators().parametersVsHash() + encodedHash;
	}
	public static HashParametersAndHash decodeHashParametersAndHash(@NotNull final String actualHashParametersAndHash, @NotNull final HashConstantParameters expectedHashConstantParameters, @NotNull final HashVariableParameters expectedHashVariableParameters) {
	    final List<String>   actualParametersAndHashEncoded = StringUtil.split(actualHashParametersAndHash, expectedHashConstantParameters.encodeDecode().separators().parametersVsHash());
		final String         actualParametersEncoded        = (actualParametersAndHashEncoded.size() == 1) ? "" : actualParametersAndHashEncoded.removeFirst();
		final String         actualHashEncoded              = actualParametersAndHashEncoded.removeFirst();
		final HashParameters actualHashParameters     = decodeHashParameters(actualParametersEncoded, expectedHashConstantParameters, expectedHashVariableParameters);
		final byte[]         actualHashBytes          = decodeHash(expectedHashConstantParameters, actualHashEncoded);
		if (actualParametersAndHashEncoded.isEmpty()) {
			return new HashParametersAndHash(actualHashParameters, actualHashBytes);
		}
		throw new RuntimeException("Leftover parts");
	}
	private static String encodeHashParameters(@NotNull final HashParameters hashParameters) {
		final HashVariableParameters hashVariableParameters = hashParameters.hashVariableParameters();
		final HashConstantParameters hashConstantParameters = hashParameters.hashConstantParameters();
		final EncodeDecode           encodeDecode           = hashConstantParameters.encodeDecode();
		final List<Object>           hashParametersValues   = new ArrayList<>();
		if (encodeDecode.flags().hashVariableParameters()) {
			hashParametersValues.add(encodeDecode.encoderDecoder().encodeToString(hashVariableParameters.hashSaltBytes()));
		}
		if (encodeDecode.flags().hashConstantParameters()) {
			hashParametersValues.addAll(hashConstantParameters.canonicalObjects());
		}
		return StringUtil.toString("", encodeDecode.separators().intraParameters(), "", hashParametersValues);
	}

	private static HashParameters decodeHashParameters(final String encodedParameters, @NotNull final HashConstantParameters expectedHashConstantParameters, @NotNull final HashVariableParameters expectedHashVariableParameters) {
		final EncodeDecode           encodeDecode                 = expectedHashConstantParameters.encodeDecode();
		final List<String>           parametersEncoded            = StringUtil.split(encodedParameters, encodeDecode.separators().intraParameters());
	    final byte[]                 expectedSaltBytes            = expectedHashVariableParameters.hashSaltBytes();
		final byte[]                 actualSaltBytes              = (encodeDecode.flags().hashVariableParameters())  ? encodeDecode.encoderDecoder().decodeFromString(parametersEncoded.removeFirst()) : expectedSaltBytes;
		final HashVariableParameters actualHashVariableParameters = new HashVariableParameters(actualSaltBytes);
		final HashConstantParameters actualHashConstantParameters = expectedHashConstantParameters.decode(parametersEncoded, encodeDecode);
		if (parametersEncoded.isEmpty()) {
			return new HashParameters(actualHashConstantParameters, actualHashVariableParameters);
		}
		throw new RuntimeException("Leftover parts");
	}

	private static String encodeHash(@NotNull final HashConstantParameters hashConstantParameters, @NotEmpty final byte[] hash) {
		return hashConstantParameters.encodeDecode().encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeHash(@NotNull final HashConstantParameters hashConstantParameters, @NotEmpty final String encodedHash) {
		return hashConstantParameters.encodeDecode().encoderDecoder().decodeFromString(encodedHash);
	}
}
