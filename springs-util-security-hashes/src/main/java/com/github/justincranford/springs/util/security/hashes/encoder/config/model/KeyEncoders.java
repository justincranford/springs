package com.github.justincranford.springs.util.security.hashes.encoder.config.model;

import java.util.LinkedHashMap;

public class KeyEncoders extends Encoders<KeyEncoder> {
	public KeyEncoders(final String id, final LinkedHashMap<String, KeyEncoder> map) {
		super(id, map);
	}
}
