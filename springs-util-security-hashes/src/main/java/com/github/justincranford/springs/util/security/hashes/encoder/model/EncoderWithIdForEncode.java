package com.github.justincranford.springs.util.security.hashes.encoder.model;

import org.springframework.security.crypto.password.PasswordEncoder;

public interface EncoderWithIdForEncode extends PasswordEncoder {
	public String idForEncode();
}
