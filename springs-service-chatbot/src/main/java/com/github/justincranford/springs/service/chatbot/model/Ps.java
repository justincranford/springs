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

import java.time.OffsetDateTime;
import java.util.List;

public class Ps {
    public static final String URL = "/api/ps";

    @Getter(onMethod = @__(@JsonProperty))
    @Setter
    @Accessors(fluent = true)
    @JsonIgnoreProperties
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @ToString
    public static class Response extends Abstract.Response {
        @JsonProperty("models")
        private List<Model> models;

        @Getter(onMethod = @__(@JsonProperty))
        @Setter
        @Accessors(fluent = true)
        @NoArgsConstructor
        @AllArgsConstructor
        @Builder
        @ToString
        public static class Model {
            @JsonProperty("name")
            private String name;

            @JsonProperty("model")
            private String model;

            @JsonProperty("size")
            private Long size;

            @JsonProperty("digest")
            private String digest;

            @JsonProperty("details")
            private Details details;

            @JsonProperty("expires_at")
            private OffsetDateTime expiresAt;

            @JsonProperty("size_vram")
            private Long sizeVram;
        }

        @Getter(onMethod = @__(@JsonProperty))
        @Setter
        @Accessors(fluent = true)
        @NoArgsConstructor
        @AllArgsConstructor
        @Builder
        @ToString
        public static class Details {
            @JsonProperty("parent_model")
            private String parentModel;

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
