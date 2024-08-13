package com.github.justincranford.springs.util.basic;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Util {
	public static final Encoder STD_ENCODE = new Encoder(Base64.getEncoder().withoutPadding());
	public static final Decoder STD_DECODE = new Decoder(Base64.getDecoder());

    private static final byte[] CRLF = new byte[] {'\r', '\n'};
    private static final byte[] LF = new byte[] {'\n'};
	public static final Encoder MIME76_ENCODE = new Encoder(Base64.getMimeEncoder(76, CRLF).withoutPadding());
	public static final Encoder MIME_ENCODE = new Encoder(Base64.getMimeEncoder(Integer.MAX_VALUE, LF).withoutPadding());
	public static final Decoder MIME_DECODE = new Decoder(Base64.getMimeDecoder());

	public static final Encoder URL_ENCODE = new Encoder(Base64.getUrlEncoder().withoutPadding());
	public static final Decoder URL_DECODE = new Decoder(Base64.getUrlDecoder());

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
}
