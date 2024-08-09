package com.github.justincranford.springs.util.json.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.time.OffsetDateTime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.util.basic.util.Base64Util;
import com.github.justincranford.springs.util.basic.util.DateTimeUtil;
import com.github.justincranford.springs.util.basic.util.SecureRandomUtil;

import lombok.extern.slf4j.Slf4j;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes={SpringsUtilJsonConfiguration.class})
@SuppressWarnings("nls")
@Slf4j
public class SpringsUtilJsonConfigurationTest {
	private static record Pojo(Integer integer, String string, OffsetDateTime offsetDateTime) { }

	@Autowired
	private ObjectMapper objectMapper;

	@Test
	void testSerializeDeserializeNonNulls() throws IOException {
		helper(new Pojo(Integer.valueOf(SecureRandomUtil.SECURE_RANDOM.nextInt()), Base64Util.MIME_ENCODE.string(SecureRandomUtil.staticRandomBytes(32)), DateTimeUtil.nowUtcTruncatedToNanoseconds()));
	}

	@Test
	void testSerializeDeserializeNulls() throws IOException {
		helper(new Pojo(null, null, null));
	}

	private void helper(final Pojo pojo) throws IOException {
		log.atDebug().addArgument(() -> pojo).log("pojo: {}");
		final String serialized = this.objectMapper.writeValueAsString(pojo);
		log.atDebug().addArgument(() -> serialized).log("serialized: {}");
		final Pojo deserialized = this.objectMapper.readValue(serialized, Pojo.class);
		log.atDebug().addArgument(() -> deserialized).log("deserialized: {}");
		assertThat(deserialized).isEqualTo(pojo);
	}
}
