package com.github.justincranford.springs.service.chatbot.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

public class Pull {
	@SuppressWarnings({"nls"})
	public static final String URL = "/api/pull";

	@Getter(onMethod=@__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@Builder
	@ToString(exclude={})
	public static class Request extends Abstract.Request {
	    @JsonProperty("model")
	    private String model;

	    @JsonProperty("keep_alive")
	    private Long keepAlive;

	    @JsonProperty("stream")
	    private Boolean stream;
	}

	@Getter(onMethod=@__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	@ToString(exclude={})
	public static class Response extends Abstract.Response {
	    @JsonProperty("reply")
	    private String reply;
	}
}
