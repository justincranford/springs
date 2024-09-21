package com.github.justincranford.springs.util.basic;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

@SuppressWarnings({"nls"})
public interface TextCodec {
	public static final HexCodec HEX_UC_STRICT  = new HexCodec(true,  true,  "HexUpperCaseStrict");
	public static final HexCodec HEX_UC_LENIENT = new HexCodec(true,  false, "HexUpperCaseLenient");
	public static final HexCodec HEX_LC_STRICT  = new HexCodec(false, true,  "HexLowerCaseStrict");
	public static final HexCodec HEX_LC_LENIENT = new HexCodec(false, false, "HexLowerCaseLenient");

	public static final Base64Codec B64_STD    = new Base64Codec(Constants.STD_ENCODER,    Constants.STD_DECODER,  "Base64");
	public static final Base64Codec B64_URL    = new Base64Codec(Constants.URL_ENCODER,    Constants.URL_DECODER,  "Base64URL");
	public static final Base64Codec B64_MIME32 = new Base64Codec(Constants.MIME32_ENCODER, Constants.MIME_DECODER, "Base64Mime32");
	public static final Base64Codec B64_MIME64 = new Base64Codec(Constants.MIME64_ENCODER, Constants.MIME_DECODER, "Base64Mime64");
	public static final Base64Codec B64_MIME76 = new Base64Codec(Constants.MIME76_ENCODER, Constants.MIME_DECODER, "Base64Mime76");
	public static final Base64Codec B64_MIME   = new Base64Codec(Constants.MIME_ENCODER,   Constants.MIME_DECODER, "Base64Mime");

	public byte[] canonicalIdBytes();
    public String encodeToString(final byte[] bytes);
    public byte[] encodeToBytes(final byte[] bytes);
    public byte[] decodeFromString(final String string);
    public byte[] decodeFromBytes(final byte[] bytes);

	public static class HexCodec implements TextCodec {
		private final byte[]  utf8HexBytes;
		private final boolean encodeUpperCase;
		private final boolean decodeStrict;
		private final byte[]  canonicalIdBytes;
    	/*package*/ HexCodec(final boolean encodeUpperCase0, final boolean decodeStrict0, final String canonicalId) {
    		this.utf8HexBytes     = encodeUpperCase0 ? Constants.HEX_UC_BYTES : Constants.HEX_LC_BYTES;
    		this.encodeUpperCase  = encodeUpperCase0;
    		this.decodeStrict     = decodeStrict0;
    		this.canonicalIdBytes = canonicalId.getBytes(StandardCharsets.UTF_8);
    	}
    	@Override
		public byte[] canonicalIdBytes() {
			return this.canonicalIdBytes;
		}
    	@Override
        public String encodeToString(final byte[] bytes) {
    		final byte[] hex = encodeToBytes(requireNonNull(bytes, "Bytes must be non-null"));
			return new String(hex, 0, hex.length, StandardCharsets.UTF_8);
    	}
    	@Override
        public byte[] encodeToBytes(final byte[] bytes) {
    		final byte[] encodedBytes = new byte[requireNonNull(bytes, "Bytes must be non-null").length * 2];
	        for (int i = 0, o = 0; i < bytes.length; ) {
	        	final int b = bytes[i++] & 0xFF;
	        	encodedBytes[o++] = this.utf8HexBytes[b >>> 4];
	        	encodedBytes[o++] = this.utf8HexBytes[b & 0x0F];
	        }
    		return encodedBytes;
    	}
    	@Override
        public byte[] decodeFromString(final String string) {
    		return decodeFromBytes(requireNonNull(string, "String must be non-null").getBytes(StandardCharsets.UTF_8));
    	}
    	@Override
        public byte[] decodeFromBytes(final byte[] bytes) {
            if (requireNonNull(bytes, "Bytes must be non-null").length % 2 != 0) {
                throw new IllegalArgumentException("Input must have even length");
            }
            final byte[] decodingBytes = this.decodeStrict ? bytes : this.encodeUpperCase
            		? new String(bytes, StandardCharsets.UTF_8).toUpperCase().getBytes(StandardCharsets.UTF_8)
            		: new String(bytes, StandardCharsets.UTF_8).toLowerCase().getBytes(StandardCharsets.UTF_8);

    		final byte[] decodedBytes = new byte[decodingBytes.length / 2];
            for (int i = 0, o = 0; i < decodingBytes.length; ) {
                final int highHalfByte = utf8HexCharToByte(decodingBytes[i++]);
                final int lowNibble  = utf8HexCharToByte(decodingBytes[i++]);
                decodedBytes[o++] = (byte) ((highHalfByte << 4) | lowNibble);
            }
            return decodedBytes;
        }
        private int utf8HexCharToByte(final byte character) {
            for (int i = 0; i < this.utf8HexBytes.length; i++) {
                if (this.utf8HexBytes[i] == character) {
                    return i;
                }
            }
            throw new IllegalArgumentException("Invalid character, expected hex character");
        }
    }

	public static class Base64Codec implements TextCodec {
    	private final Base64.Encoder encoder;
    	private final Base64.Decoder decoder;
    	private final byte[] canonicalIdBytes;
    	/*package*/ Base64Codec(final Base64.Encoder encoder0, final Base64.Decoder decoder0, final String canonicalId) {
    		this.encoder = encoder0;
    		this.decoder = decoder0;
    		this.canonicalIdBytes = canonicalId.getBytes(StandardCharsets.UTF_8);
    	}
    	@Override
		public byte[] canonicalIdBytes() {
			return this.canonicalIdBytes;
		}
    	@Override
        public String encodeToString(final byte[] bytes) {
    		final byte[] base64 = encodeToBytes(requireNonNull(bytes, "Bytes must be non-null"));
			return new String(base64, 0, base64.length, StandardCharsets.UTF_8);
    	}
    	@Override
        public byte[] encodeToBytes(final byte[] bytes) {
    		return this.encoder.encode(requireNonNull(bytes, "Bytes must be non-null"));
    	}
    	@Override
        public byte[] decodeFromString(final String string) {
    		return decodeFromBytes(requireNonNull(string, "String must be non-null").getBytes(StandardCharsets.UTF_8));
    	}
    	@Override
        public byte[] decodeFromBytes(final byte[] bytes) {
    		return this.decoder.decode(requireNonNull(bytes, "Bytes must be non-null"));
    	}
    }

	public static class Constants {
		public static final byte[] HEX_UC_BYTES = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
		public static final byte[] HEX_LC_BYTES = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

		public static final byte[] CRLF = new byte[] {'\r', '\n'};
		public static final byte[] LF = new byte[] {'\n'};

	    public static final Base64.Encoder STD_ENCODER = Base64.getEncoder().withoutPadding();
		public static final Base64.Decoder STD_DECODER = Base64.getDecoder();
		public static final Base64.Encoder MIME32_ENCODER = Base64.getMimeEncoder(32, LF).withoutPadding();
		public static final Base64.Encoder MIME64_ENCODER = Base64.getMimeEncoder(64, CRLF).withoutPadding();
		public static final Base64.Encoder MIME76_ENCODER = Base64.getMimeEncoder(76, CRLF).withoutPadding();
		public static final Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder(Integer.MAX_VALUE, LF).withoutPadding();
		public static final Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();
	    public static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
		public static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
	}
}
