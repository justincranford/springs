package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.Getter;
import lombok.experimental.Accessors;

@Getter
@Accessors(fluent=true)
@SuppressWarnings({"deprecation", "rawtypes", "unchecked"})
public abstract class Encoders<ENCODERCLASS extends Encoder> extends DelegatingPasswordEncoder implements EncoderWithIdForEncode {
	// TODO upgradeEncoding true
	private static final PasswordEncoder NOOP_PASSWORD_ENCODER = NoOpPasswordEncoder.getInstance();

	private final String idForEncode;
	private final LinkedHashMap<String, ENCODERCLASS> idToEncoders;
	public Encoders(final String id, final LinkedHashMap<String, ENCODERCLASS> map) {
		super(id, (Map) map);
		this.idForEncode = id;
		this.idToEncoders = map;
		super.setDefaultPasswordEncoderForMatches(NOOP_PASSWORD_ENCODER);
	}
}
