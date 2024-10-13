package com.github.justincranford.springs.util.json.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

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
			log.info(pojo.getClass().getSimpleName() + " (JSON):\n{}", this.objectWriter.writeValueAsString(pojo));
			return pojo;
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}
}
