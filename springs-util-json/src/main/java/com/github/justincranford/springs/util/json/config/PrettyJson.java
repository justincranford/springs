package com.github.justincranford.springs.util.json.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

@Component
@Slf4j
@SuppressWarnings({"nls"})
public class PrettyJson {
	@Autowired
	private ObjectMapper objectMapper;

	private ObjectWriter objectWriter;

	@PostConstruct
	public void postConstruct() {
		this.objectWriter = this.objectMapper.writer().withDefaultPrettyPrinter();
	}

	public <T> T log(final T pojo) {
		try {
			final String clazz = pojo.getClass().getSimpleName();
			log.info(clazz + " (toString):\n{}", pojo);
			final String json = this.objectWriter.writeValueAsString(pojo);
			log.info(clazz + " (JSON):\n{}", json);
			return pojo;
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	public <T> T logAndSave(final T pojo) throws IOException {
		try {
			final String clazz = pojo.getClass().getSimpleName();
			log.info(clazz + " (toString):\n{}", pojo);

			final String json = this.objectWriter.writeValueAsString(pojo);
			log.info(clazz + " (JSON):\n{}", json);

			final String nowString = DateTimeUtil.nowUtcTruncatedToMilliseconds().toString()
				.replaceAll("-", "")
				.replaceAll(":", "")
				.replace("Z", "-")
				.replace("T", "-");
			final Path path = Paths.get("target", nowString + clazz + ".json");
			Files.write(path, json.getBytes(StandardCharsets.UTF_8));
			return pojo;
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	public <T> String pretty(final T pojo) {
		try {
			return this.objectWriter.writeValueAsString(pojo).toString();
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}
}
