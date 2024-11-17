package com.github.justincranford.springs.service.chatbot.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@SuppressWarnings({"unused"})
public class Options {
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
