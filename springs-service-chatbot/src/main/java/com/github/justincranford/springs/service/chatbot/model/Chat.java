package com.github.justincranford.springs.service.chatbot.model;

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

@SuppressWarnings({"nls"})
public class Chat {
	public static final String URL = "/api/chat";

	@Getter(onMethod=@__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	@ToString(exclude={})
	public static class Request extends Abstract.Request {
	    @JsonProperty("model")
	    private String model;
	
	    @JsonProperty("keep_alive")
	    private Long keepAlive;

	    @JsonProperty("stream")
	    private Boolean stream;
	
	    @JsonProperty("messages")
	    private List<Message> messages;
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
	    @JsonProperty("model")
	    private String model;

	    @JsonProperty("created_at")
	    private String createdAt;

	    @JsonProperty("message")
	    private Message message;

	    @JsonProperty("done")
	    private Boolean done;

	    @JsonProperty("done_reason")
	    private String doneReason;

	    @JsonProperty("error")
	    private String error;

	    @JsonProperty("context")
	    private List<Integer> context;

	    @JsonProperty("total_duration")
	    private Long totalDuration;

	    @JsonProperty("load_duration")
	    private Long loadDuration;

	    @JsonProperty("prompt_eval_count")
	    private Integer promptEvalCount;

	    @JsonProperty("prompt_eval_duration")
	    private Long promptEvalDuration;

	    @JsonProperty("eval_count")
	    private Integer evalCount;

	    @JsonProperty("eval_duration")
	    private Long evalDuration;
    }
}
