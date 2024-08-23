package com.github.justincranford.springs.util.security.hashes.encoder;

import java.util.LinkedHashMap;

public class ValueEncoders extends Encoders<ValueEncoder> {
	public ValueEncoders(final String id, final LinkedHashMap<String, ValueEncoder> map) {
		super(id, map);
	}
}