package com.github.justincranford.springs.util.security.hashes.encoder.pepper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstants;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantsAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashParametersAndHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashVariables;
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
		@NotNull final HashConstantsAndHashPeppers    expectedHashConstantsAndHashPeppers,
		@NotNull final Function<CharSequence, byte[]> expectedSaltSupplier
	) {
		final HashConstants expectedHashConstants = expectedHashConstantsAndHashPeppers.hashConstants();
		final HashPeppers   hashPeppers           = expectedHashConstantsAndHashPeppers.hashPeppers();
		super.encode = (rawInput) -> {
			final HashVariables  actualHashVariables  = new HashVariables(expectedSaltSupplier.apply(rawInput));
			final HashParameters actualHashParameters = new HashParameters(expectedHashConstants, actualHashVariables);
			final byte[]         actualHashBytes      = computeHash(rawInput, actualHashParameters, hashPeppers);
			return encodeHashParametersAndHash(actualHashParameters, actualHashBytes);
		};
		super.matches = (rawInput, actualHashParametersAndHashEncoded) -> {
			final HashVariables         expectedHashVariables       = new HashVariables(expectedSaltSupplier.apply(rawInput));
			final HashParametersAndHash actualHashParametersAndHash = decodeHashParametersAndHash(actualHashParametersAndHashEncoded, expectedHashConstants, expectedHashVariables);
			final HashParameters        actualHashParameters        = actualHashParametersAndHash.hashParameters();
			final byte[]                actualHashBytes             = actualHashParametersAndHash.hashBytes();
			final byte[]                expectedHashBytes           = computeHash(rawInput, actualHashParameters, hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(expectedHashBytes, actualHashBytes));
		};
		super.upgradeEncoding = (actualHashParametersAndHashEncoded) -> {
			if (actualHashParametersAndHashEncoded == null || actualHashParametersAndHashEncoded.length() == 0) {
				return Boolean.FALSE;
			}
			final CharSequence          expectedRawInput = "";
			final int                   expectedSaltBytesLength     = hashPeppers.hashSaltPepper().pepper().outputBytesLength(expectedSaltSupplier.apply(expectedRawInput).length);
			final int                   expectedHashBytesLength     = hashPeppers.hashPostHashPepper().pepper().outputBytesLength(expectedRawInput.length());
			final HashVariables         expectedHashVariables       = new HashVariables(new byte[expectedSaltBytesLength]);
			final HashParametersAndHash actualHashParametersAndHash = decodeHashParametersAndHash(actualHashParametersAndHashEncoded, expectedHashConstants, expectedHashVariables);
			final HashParameters        actualHashParameters        = actualHashParametersAndHash.hashParameters();
			final HashConstants         actualConstants             = actualHashParameters.hashConstants();
			final HashVariables         actualVariables             = actualHashParameters.hashVariables();
			final int                   actualSaltBytesLength       = actualVariables.hashSaltBytes().length;
			final int                   actualHashBytesLength       = optionalTextDecode(hashPeppers.hashPostHashPepper().pepper(), actualHashParametersAndHash.hashBytes()).length;
			return expectedHashConstants.recompute(expectedSaltBytesLength, actualSaltBytesLength, actualConstants, expectedHashBytesLength, actualHashBytesLength);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final HashParameters hashParameters, final HashPeppers hashPeppers) {
		final HashConstants hashConstants       = hashParameters.hashConstants();
		final byte[]        plainSaltBytes      = hashParameters.hashVariables().hashSaltBytes();
		final byte[]        additionalDataBytes = hashParameters.canonicalBytes();
		final byte[]        pepperedSaltBytes   = optionalPepperAndTextEncode(hashPeppers.hashSaltPepper().pepper(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]        plainInputBytes     = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]        pepperedInputBytes  = optionalPepperAndTextEncode(hashPeppers.hashPreHashPepper().pepper(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String        pepperedInputString = new String(pepperedInputBytes, StandardCharsets.UTF_8);
		final byte[]        plainHashBytes      = computeHash(hashConstants, pepperedSaltBytes, pepperedInputString);
		final byte[]        pepperedHashBytes   = optionalPepperAndTextEncode(hashPeppers.hashPostHashPepper().pepper(), plainHashBytes, additionalDataBytes); // post-hash step (aka pepper)
		return pepperedHashBytes;
	}

	private static byte[] optionalPepperAndTextEncode(@Null final Pepper pepper, @NotEmpty final byte[] bytes, @NotNull final byte[] additionalData) {
		return (pepper == null) ? bytes : pepper.compute(bytes, additionalData);
	}
	private static byte[] optionalTextDecode(@Null final Pepper pepper, @NotNull final byte[] bytes) {
		return (pepper == null) ? bytes : pepper.encoderDecoder().decodeFromBytes(bytes);
	}

	private static byte[] computeHash(@NotNull final HashConstants hashConstants, @NotNull final byte[] saltBytes, @NotNull final CharSequence rawInput) {
		return hashConstants.compute(saltBytes, rawInput);
	}

	private static String encodeHashParametersAndHash(@NotNull final HashParameters actualHashParameters, @NotEmpty final byte[] actualHashBytes) {
		final String actualHashParametersEncoded = encodeHashParameters(actualHashParameters);
		final String actualHashEncoded           = encodeHash(actualHashParameters.hashConstants(), actualHashBytes);
		if (actualHashParametersEncoded.isEmpty()) {
			return actualHashEncoded;
		}
		return actualHashParametersEncoded + actualHashParameters.hashConstants().encodeDecode().separators().parametersVsHash() + actualHashEncoded;
	}
	public static HashParametersAndHash decodeHashParametersAndHash(@NotNull final String actualHashParametersAndHashEncoded, @NotNull final HashConstants expectedHashConstants, @NotNull final HashVariables expectedHashVariables) {
	    final List<String>   actualParametersAndHashEncoded = StringUtil.split(actualHashParametersAndHashEncoded, expectedHashConstants.encodeDecode().separators().parametersVsHash());
		final String         actualParametersEncoded        = (actualParametersAndHashEncoded.size() == 1) ? "" : actualParametersAndHashEncoded.removeFirst();
		final String         actualHashEncoded              = actualParametersAndHashEncoded.removeFirst();
		if (!actualParametersAndHashEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		final HashParameters actualHashParameters           = decodeHashParameters(actualParametersEncoded, expectedHashConstants, expectedHashVariables);
		final byte[]         actualHashBytes                = decodeHash(expectedHashConstants, actualHashEncoded);
		return new HashParametersAndHash(actualHashParameters, actualHashBytes);
	}
	private static String encodeHashParameters(@NotNull final HashParameters actualHashParameters) {
		final HashVariables actualHashVariables  = actualHashParameters.hashVariables();
		final HashConstants actualHashConstants  = actualHashParameters.hashConstants();
		final EncodeDecode  encodeDecode         = actualHashConstants.encodeDecode();
		final List<Object>  hashParametersValues = new ArrayList<>();
		if (encodeDecode.flags().encodeHashVariables()) {
			hashParametersValues.add(encodeDecode.encoderDecoder().encodeToString(actualHashVariables.hashSaltBytes()));
		}
		if (encodeDecode.flags().encodeHashConstants()) {
			hashParametersValues.addAll(actualHashConstants.canonicalObjects());
		}
		return StringUtil.toString("", encodeDecode.separators().intraParameters(), "", hashParametersValues);
	}

	private static HashParameters decodeHashParameters(final String actualParametersEncoded, @NotNull final HashConstants expectedHashConstants, @NotNull final HashVariables expectedHashVariables) {
		final EncodeDecode  encodeDecode        = expectedHashConstants.encodeDecode();
		final List<String>  parametersEncoded   = StringUtil.split(actualParametersEncoded, encodeDecode.separators().intraParameters());
	    final byte[]        expectedSaltBytes   = expectedHashVariables.hashSaltBytes();
		final byte[]        actualSaltBytes     = (encodeDecode.flags().encodeHashVariables())  ? encodeDecode.encoderDecoder().decodeFromString(parametersEncoded.removeFirst()) : expectedSaltBytes;
		final HashVariables actualHashVariables = new HashVariables(actualSaltBytes);
		final HashConstants actualHashConstants = expectedHashConstants.decode(parametersEncoded, encodeDecode);
		if (!parametersEncoded.isEmpty()) {
			throw new RuntimeException("Leftover parts");
		}
		return new HashParameters(actualHashConstants, actualHashVariables);
	}

	private static String encodeHash(@NotNull final HashConstants actualHashConstants, @NotEmpty final byte[] actualHashBytes) {
		return actualHashConstants.encodeDecode().encoderDecoder().encodeToString(actualHashBytes);
	}
	private static byte[] decodeHash(@NotNull final HashConstants actualHashConstants, @NotEmpty final String actualHashEncoded) {
		return actualHashConstants.encodeDecode().encoderDecoder().decodeFromString(actualHashEncoded);
	}
}
