package com.github.justincranford.springs.service.chatbot.model;

import java.util.List;

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
		  protected abstract Options options();

		  @JsonProperty("template")
		  protected abstract String template();
		  
		  @JsonProperty("format")
		  protected abstract Boolean format();
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

	@Getter(onMethod=@__(@JsonProperty))
	@Setter
	@Accessors(fluent=true)
	@JsonIgnoreProperties
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	@ToString(exclude={})
	public static class Options {
	    @JsonProperty("mirostat")
	    private Integer mirostat;

	    @JsonProperty("mirostat_eta")
	    private Double mirostatEta;

	    @JsonProperty("mirostat_tau")
	    private Double mirostatTau;

	    @JsonProperty("num_ctx")
	    private Integer numCtx;

	    @JsonProperty("repeat_last_n")
	    private Integer repeatLastN;

	    @JsonProperty("repeat_penalty")
	    private Double repeatPenalty;

	    @JsonProperty("temperature")
	    private Double temperature;

	    @JsonProperty("seed")
	    private Integer seed;

	    @JsonProperty("stop")
	    private List<String> stop;

	    @JsonProperty("tfs_z")
	    private Double tfsZ;

	    @JsonProperty("num_predict")
	    private Integer numPredict;

	    @JsonProperty("top_k")
	    private Integer topK;

	    @JsonProperty("top_p")
	    private Double topP;

	    @JsonProperty("min_p")
	    private Double minP;
	}
}
