package com.github.justincranford.springs.util.basic;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Util {
	public static final EncoderDecoder STD    = new EncoderDecoder(Constants.STD_ENCODER,    Constants.STD_DECODER);
	public static final EncoderDecoder MIME32 = new EncoderDecoder(Constants.MIME32_ENCODER, Constants.MIME_DECODER);
	public static final EncoderDecoder MIME64 = new EncoderDecoder(Constants.MIME64_ENCODER, Constants.MIME_DECODER);
	public static final EncoderDecoder MIME76 = new EncoderDecoder(Constants.MIME76_ENCODER, Constants.MIME_DECODER);
	public static final EncoderDecoder MIME   = new EncoderDecoder(Constants.MIME_ENCODER,   Constants.MIME_DECODER);
	public static final EncoderDecoder URL    = new EncoderDecoder(Constants.URL_ENCODER,    Constants.URL_DECODER);

	public static class EncoderDecoder {
    	private final Base64.Encoder encoder;
    	private final Base64.Decoder decoder;
    	public EncoderDecoder(final Base64.Encoder encoder0, final Base64.Decoder decoder0) {
    		this.encoder = encoder0;
    		this.decoder = decoder0;
    	}
        public String encodeToString(final byte[] bytes) {
    		final byte[] base64 = encodeToBytes(bytes);
			return new String(base64, 0, base64.length, StandardCharsets.UTF_8);
    	}
        public byte[] encodeToBytes(final byte[] bytes) {
    		return this.encoder.encode(bytes);
    	}

        public byte[] decodeFromString(final String string) {
    		return decodeFromBytes(string.getBytes(StandardCharsets.UTF_8));
    	}
        public byte[] decodeFromBytes(final byte[] bytes) {
    		return this.decoder.decode(bytes);
    	}
    }

	private static class Constants {
	    private static final byte[] CRLF = new byte[] {'\r', '\n'};
	    private static final byte[] LF = new byte[] {'\n'};

	    private static final Base64.Encoder STD_ENCODER = Base64.getEncoder().withoutPadding();
		private static final Base64.Decoder STD_DECODER = Base64.getDecoder();
		private static final Base64.Encoder MIME32_ENCODER = Base64.getMimeEncoder(32, LF).withoutPadding();
		private static final Base64.Encoder MIME64_ENCODER = Base64.getMimeEncoder(64, CRLF).withoutPadding();
		private static final Base64.Encoder MIME76_ENCODER = Base64.getMimeEncoder(76, CRLF).withoutPadding();
		private static final Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder(Integer.MAX_VALUE, LF).withoutPadding();
		private static final Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();
	    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
		private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
	}
}
