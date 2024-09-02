package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public abstract class AbstractEncoderV1 extends IocEncoder {
	public AbstractEncoderV1(
		@NotNull final ParametersAndMacs parametersAndMacs,
		@NotNull final Function<CharSequence, byte[]> saltSupplier
	) {
		final Parameters parameters = parametersAndMacs.parameters();
		final Macs       macs       = parametersAndMacs.macs();
		super.encode = (rawInput) -> {
			final byte[]            saltBytes         = saltSupplier.apply(rawInput);
			final ParametersAndSalt parametersAndSalt = new ParametersAndSalt(parameters, saltBytes);
			final byte[]            hashBytes         = computeHash(rawInput, parametersAndSalt, macs);
			return encodeParametersAndSaltAndHash(parametersAndSalt, hashBytes);
		};
		super.matches = (rawInput, encodedParametersAndSaltAndHash) -> {
			final byte[]                   saltBytes                = saltSupplier.apply(rawInput);
			final ParametersAndSaltAndHash parametersAndSaltAndHash = decodeParametersAndSaltAndHash(encodedParametersAndSaltAndHash, parameters, saltBytes);
			final byte[]                   hashBytes                = computeHash(rawInput, parametersAndSaltAndHash.parametersAndSalt(), macs);
			return Boolean.valueOf(MessageDigest.isEqual(hashBytes, parametersAndSaltAndHash.hash()));
		};
		super.upgradeEncoding = (encodedParametersAndSaltAndHash) -> {
			if (encodedParametersAndSaltAndHash == null || encodedParametersAndSaltAndHash.length() == 0) {
				return Boolean.FALSE;
			}
			final byte[]                   saltBytes                = saltSupplier.apply(""); // value not used, only its length
			final ParametersAndSaltAndHash parametersAndSaltAndHash = decodeParametersAndSaltAndHash(encodedParametersAndSaltAndHash, parameters, saltBytes);
			final ParametersAndSalt        parametersAndSaltDecoded = parametersAndSaltAndHash.parametersAndSalt();
			final Parameters               parametersDecoded        = parametersAndSaltDecoded.parameters();
			final byte[]                   saltBytesDecoded         = parametersAndSaltDecoded.saltBytes();
			final byte[]                   spicyHashBytes           = parametersAndSaltAndHash.hash();
			final byte[]                   spicyHashDecodedBytes    = optionalMacDecode(macs.postHash().mac(), spicyHashBytes);
			return parameters.upgradeEncoding(saltBytes.length, saltBytesDecoded.length, parametersDecoded, spicyHashDecodedBytes.length);
		};
	}

	private static byte[] computeHash(final CharSequence rawInput, final ParametersAndSalt parametersAndSalt, final Macs macs) {
		final Parameters parameters          = parametersAndSalt.parameters();
		final byte[]     plainSaltBytes      = parametersAndSalt.saltBytes();
		final byte[]     additionalDataBytes = parametersAndSalt.canonicalEncodedBytes();
		final byte[]     spicySaltBytes      = optionalMacAndEncode(macs.preSalt().mac(), plainSaltBytes, additionalDataBytes); // pre-salt step
		final byte[]     plainInputBytes     = rawInput.toString().getBytes(StandardCharsets.UTF_8);
		final byte[]     spicyInputBytes     = optionalMacAndEncode(macs.preHash().mac(), plainInputBytes, additionalDataBytes); // pre-hash step
		final String     spicyInputString    = new String(spicyInputBytes, StandardCharsets.UTF_8);
		final byte[]     plainHashBytes      = computeHash(parameters, spicySaltBytes, spicyInputString);
		final byte[]     spicyHashBytes      = optionalMacAndEncode(macs.postHash().mac(), plainHashBytes, additionalDataBytes); // post-hash step (aka pepper)
		return spicyHashBytes;
	}

	private static byte[] optionalMacAndEncode(@Null final Mac mac, @NotEmpty final byte[] bytes, @NotNull final byte[] additionalData) {
		return (mac == null) ? bytes : mac.compute(bytes, additionalData);
	}
	private static byte[] optionalMacDecode(@Null final Mac mac, @NotNull final byte[] spicyHashBytes) {
		return (mac == null) ? spicyHashBytes : mac.encoderDecoder().decodeFromBytes(spicyHashBytes);
	}

	private static byte[] computeHash(@NotNull final Parameters parameters, @NotNull final byte[] saltBytes, @NotNull final CharSequence rawInput) {
		return parameters.computeHash(saltBytes, rawInput);
	}
	
	private static String encodeParametersAndSaltAndHash(@NotNull final ParametersAndSalt parametersAndSalt, @NotEmpty final byte[] hashBytes) {
		final String encodedParametersAndSalt = encodeParametersAndSalt(parametersAndSalt);
		final String encodedHash              = encodeClearHash(parametersAndSalt.parameters().hashEncodeDecode().encoderDecoder(), hashBytes);
		if (encodedParametersAndSalt.isEmpty()) {
			return encodedHash;
		}
		return encodedParametersAndSalt + parametersAndSalt.parameters().hashEncodeDecode().separators().encodeHash() + encodedHash;
	}
	public static ParametersAndSaltAndHash decodeParametersAndSaltAndHash(@NotNull final String parametersAndSaltAndHash, @NotNull final Parameters parameters, @NotNull final byte[] saltBytes) {
	    final String[] parts = parametersAndSaltAndHash.split(parameters.hashEncodeDecode().separators().decodeHash());
	    int part = 0;
		final ParametersAndSalt parametersAndSalt = decodeParameters((parts.length == 1) ? "" : parts[part++], parameters, saltBytes);
		final byte[] hashBytes = decodeHash(parameters.hashEncodeDecode().encoderDecoder(), parts[part++]);
		return new ParametersAndSaltAndHash(parametersAndSalt, hashBytes);
	
	}
	private static String encodeParametersAndSalt(@NotNull final ParametersAndSalt parametersAndSalt) {
		final Parameters parameters = parametersAndSalt.parameters();
		final List<Object> parametersToBeEncoded = new ArrayList<>(4);
		final HashEncodeDecode hashEncodeDecode = parameters.hashEncodeDecode();
		if (hashEncodeDecode.flags().salt()) {
			parametersToBeEncoded.add(hashEncodeDecode.encoderDecoder().encodeToString(parametersAndSalt.saltBytes()));
		}
		if (hashEncodeDecode.flags().parameters()) {
			parametersToBeEncoded.addAll(parameters.encodeParameters());
		}
		return StringUtil.toString("", hashEncodeDecode.separators().encodeParameters(), "", parametersToBeEncoded);
	}
	
	private static ParametersAndSalt decodeParameters(final String encodedParameters, @NotNull final Parameters parameters, @NotNull final byte[] saltBytes) {
		final HashEncodeDecode hashEncodeDecode  = parameters.hashEncodeDecode();
		final String[]         parts             = encodedParameters.split(hashEncodeDecode.separators().decodeParameters());
	    int part = 0;
		final byte[]           saltBytesDecoded  = (hashEncodeDecode.flags().salt())  ? hashEncodeDecode.encoderDecoder().decodeFromString(parts[part++]) : saltBytes;
		final Parameters       parametersDecoded = parameters.decodeParameters(parts, part, hashEncodeDecode);
		return new ParametersAndSalt(parametersDecoded, saltBytesDecoded);
	}
	
	private static String encodeClearHash(@NotNull final Base64Util.EncoderDecoder encoderDecoder, @NotEmpty final byte[] hash) {
		return encoderDecoder.encodeToString(hash);
	}
	private static byte[] decodeHash(@NotNull final Base64Util.EncoderDecoder encoderDecoder, @NotEmpty final String encodedHash) {
		return encoderDecoder.decodeFromString(encodedHash);
	}
}
