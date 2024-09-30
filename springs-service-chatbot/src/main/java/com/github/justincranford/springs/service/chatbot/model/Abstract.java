package com.github.justincranford.springs.service.chatbot.model;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Getter(onMethod = @__(@JsonProperty))
@Setter
@Accessors(fluent=true)
@JsonIgnoreProperties
@NoArgsConstructor
@ToString(exclude={})
@SuppressWarnings({"nls"})
public abstract class Abstract {
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@ToString(exclude={})
	public abstract static class Request extends Abstract {
		  @JsonProperty("model")
		  protected abstract String model(); 

		  @JsonProperty("keep_alive")
		  protected abstract Long keepAlive();

		  @JsonProperty("stream")
		  protected abstract Boolean stream();

		  @JsonProperty("options")
		  protected Map<String, Object> options;

		  @JsonProperty("template")
		  protected String template;
		  
		  @JsonProperty("format")
		  protected Boolean format;
	  }

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@ToString(exclude={})
	public abstract static class Response extends Abstract {
		// do nothing
	}


	@Getter(onMethod=@__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	@ToString(exclude={})
    public static class Message {
	    @JsonProperty("role")
        private Role role;

	    @JsonProperty("content")
        private String content;

	    @JsonProperty("images")
        @JsonSerialize
        private List<byte[]> images;

	    public static enum Role {
			SYSTEM("system"),
	        USER("user"),
	        ASSISTANT("assistant");

	    	@JsonValue
	    	private String lowercase;

	    	Role(final String lowercase0) {
	    		this.lowercase = lowercase0;
	    	}
	    }
    }
}
