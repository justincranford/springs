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
		@NotNull final HashConstantParametersAndHashPeppers hashConstantParametersAndHashPeppers,
		@NotNull final Function<CharSequence, byte[]>       hashSaltSupplier
	) {
		final HashConstantParameters hashConstantParameters = hashConstantParametersAndHashPeppers.hashConstantParameters();
		final HashPeppers            hashPeppers            = hashConstantParametersAndHashPeppers.hashPeppers();
		super.encode = (rawInput) -> {
			final HashVariableParameters hashVariableParameters = new HashVariableParameters(hashSaltSupplier.apply(rawInput));
			final HashParameters         hashParameters         = new HashParameters(hashConstantParameters, hashVariableParameters);
			final byte[]                 hashBytes              = computeHash(rawInput, hashParameters, hashPeppers);
			return encodeHashParametersAndHash(hashParameters, hashBytes);
		};
		super.matches = (rawInput, encodedHashParametersAndHash) -> {
			final HashVariableParameters hashVariableParameters       = new HashVariableParameters(hashSaltSupplier.apply(rawInput));
			final HashParametersAndHash  hashParametersAndHashDecoded = decodeHashParametersAndHash(encodedHashParametersAndHash, hashConstantParameters, hashVariableParameters);
			final byte[]                 hashBytes                    = computeHash(rawInput, hashParametersAndHashDecoded.hashParameters(), hashPeppers);
			return Boolean.valueOf(MessageDigest.isEqual(hashBytes, hashParametersAndHashDecoded.hashBytes()));
		};
		super.upgradeEncoding = (encodedHashParametersAndHash) -> {
			if (encodedHashParametersAndHash == null || encodedHashParametersAndHash.length() == 0) {
				return Boolean.FALSE;
			}
			final int                    hashBytesLength               = hashSaltSupplier.apply("").length;
			final HashVariableParameters hashVariableParameters        = new HashVariableParameters(new byte[hashBytesLength]);
			final HashParametersAndHash  hashParametersAndHashDecoded  = decodeHashParametersAndHash(encodedHashParametersAndHash, hashConstantParameters, hashVariableParameters);
			final HashParameters         hashParametersDecoded         = hashParametersAndHashDecoded.hashParameters();
			final HashConstantParameters hashConstantParametersDecoded = hashParametersDecoded.hashConstantParameters();
			final HashVariableParameters hashVariableParametersDecoded = hashParametersDecoded.hashVariableParameters();
			final byte[]                 hashSaltBytesDecoded          = hashVariableParametersDecoded.hashSaltBytes();
			final byte[]                 pepperedHashBytes             = hashParametersAndHashDecoded.hashBytes();
			final byte[]                 pepperedHashDecodedBytes      = optionalDecodePepper(hashPeppers.hashPostHashPepper().pepper(), pepperedHashBytes);
			return hashConstantParameters.recompute(hashBytesLength, hashSaltBytesDecoded.length, hashConstantParametersDecoded, pepperedHashDecodedBytes.length);
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
	private static byte[] optionalDecodePepper(@Null final Pepper pepper, @NotNull final byte[] pepperedHashBytes) {
		return (pepper == null) ? pepperedHashBytes : pepper.encoderDecoder().decodeFromBytes(pepperedHashBytes);
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
	public static HashParametersAndHash decodeHashParametersAndHash(@NotNull final String hashParametersAndHash, @NotNull final HashConstantParameters defaultHashConstantParameters, @NotNull HashVariableParameters hashVariableParameters) {
	    final List<String>   parts          = StringUtil.split(hashParametersAndHash, defaultHashConstantParameters.encodeDecode().separators().parametersVsHash());
	    final byte[]         hashSaltBytes  = hashVariableParameters.hashSaltBytes();
		final HashParameters hashParameters = decodeHashParameters((parts.size() == 1) ? "" : parts.removeFirst(), defaultHashConstantParameters, hashSaltBytes);
		final byte[]         hashBytes      = decodeHash(defaultHashConstantParameters, parts.removeFirst());
		if (parts.isEmpty()) {
			return new HashParametersAndHash(hashParameters, hashBytes);
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

	private static HashParameters decodeHashParameters(final String encodedParameters, @NotNull final HashConstantParameters defaultHashConstantParameters, @NotNull final byte[] hashSaltBytes) {
		final EncodeDecode             encodeDecode                  = defaultHashConstantParameters.encodeDecode();
		final List<String>             parts                         = StringUtil.split(encodedParameters, encodeDecode.separators().intraParameters());
		final byte[]                   hashSaltBytesDecoded          = (encodeDecode.flags().hashVariableParameters())  ? encodeDecode.encoderDecoder().decodeFromString(parts.removeFirst()) : hashSaltBytes;
		final HashVariableParameters   hashVariableParametersDecoded = new HashVariableParameters(hashSaltBytesDecoded);
		final HashConstantParameters   hashConstantParametersDecoded = defaultHashConstantParameters.decode(parts, encodeDecode);
		if (parts.isEmpty()) {
			return new HashParameters(hashConstantParametersDecoded, hashVariableParametersDecoded);
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
