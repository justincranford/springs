package com.github.justincranford.springs.service.chatbot.model;

import java.time.OffsetDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

public class Tags {
	@SuppressWarnings({ "nls" })
	public static final String URL = "/api/tags";

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@Accessors(fluent = true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	@ToString(exclude = {})
	public static class Response extends Abstract.Response {
		@JsonProperty("models")
		private List<Model> models;

		@Getter(onMethod = @__(@JsonProperty))
		@Setter
		@Accessors(fluent = true)
		@JsonIgnoreProperties
		@NoArgsConstructor
		@AllArgsConstructor
		@Builder
		@ToString(exclude = {})
		public static class Model {
			@JsonProperty("name")
			private String name;

			@JsonProperty("model")
			private String model;

			@JsonProperty("modified_at")
			private OffsetDateTime modifiedAt;

			@JsonProperty("expires_at")
			private OffsetDateTime expiresAt;

			@JsonProperty("digest")
			private String digest;

			@JsonProperty("size")
			private Long size;

			@JsonProperty("modelMeta")
			private ModelMeta modelMeta;

			@Getter(onMethod = @__(@JsonProperty))
			@Setter
			@Accessors(fluent = true)
			@JsonIgnoreProperties
			@NoArgsConstructor
			@AllArgsConstructor
			@Builder
			@ToString(exclude = {})
			public static class ModelMeta {
				@JsonProperty("format")
				private String format;

				@JsonProperty("family")
				private String family;

				@JsonProperty("families")
				private List<String> families;

				@JsonProperty("parameter_size")
				private String parameterSize;

				@JsonProperty("quantization_level")
				private String quantizationLevel;
			}
		}
	}
}