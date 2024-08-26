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

	public static final Encoder STD_ENCODE = new Encoder(Constants.STD_ENCODER);
	public static final Decoder STD_DECODE = new Decoder(Constants.STD_DECODER);

	public static final Encoder MIME32_ENCODE = new Encoder(Constants.MIME32_ENCODER);
	public static final Encoder MIME76_ENCODE = new Encoder(Constants.MIME76_ENCODER);
	public static final Encoder MIME_ENCODE = new Encoder(Constants.MIME_ENCODER);
	public static final Decoder MIME_DECODE = new Decoder(Constants.MIME_DECODER);

	public static final Encoder URL_ENCODE = new Encoder(Constants.URL_ENCODER);
	public static final Decoder URL_DECODE = new Decoder(Constants.URL_DECODER);

	public static class EncoderDecoder {
    	private final Base64.Encoder encoder;
    	private final Base64.Decoder decoder;
    	public EncoderDecoder(final Base64.Encoder encoder0, final Base64.Decoder decoder0) {
    		this.encoder = encoder0;
    		this.decoder = decoder0;
    	}
        public String encodeToString(final byte[] bytes) {
    		final byte[] base64 = encodeToBytes(bytes);
			return new String(base64, 0, base64.length, StandardCharsets.US_ASCII);
    	}
        public byte[] encodeToBytes(final byte[] bytes) {
    		return this.encoder.encode(bytes);
    	}

        public byte[] decodeFromString(final String string) {
    		return decodeFromBytes(string.getBytes(StandardCharsets.US_ASCII));
    	}
        public byte[] decodeFromBytes(final byte[] bytes) {
    		return this.decoder.decode(bytes);
    	}
    }

    public static class Encoder {
    	private final Base64.Encoder encoder;
    	public Encoder(final Base64.Encoder encoder0) {
    		this.encoder = encoder0;
    	}
        public String string(final byte[] bytes) {
    		final byte[] base64 = bytes(bytes);
			return new String(base64, 0, base64.length, StandardCharsets.US_ASCII);
    	}
        public byte[] bytes(final byte[] bytes) {
    		return this.encoder.encode(bytes);
    	}
    }
    public static class Decoder {
    	private final Base64.Decoder decoder;
    	public Decoder(final Base64.Decoder decoder0) {
    		this.decoder = decoder0;
    	}
        public byte[] bytes(final String string) {
    		return bytes(string.getBytes(StandardCharsets.US_ASCII));
    	}
        public byte[] bytes(final byte[] bytes) {
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
