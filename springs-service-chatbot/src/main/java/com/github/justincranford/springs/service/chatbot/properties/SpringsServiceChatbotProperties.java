package com.github.justincranford.springs.service.chatbot.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Component
@ConfigurationProperties(prefix="springs.service.chatbot",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-service-chatbot.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsServiceChatbotProperties {
	@NotNull
	@NotEmpty
	@Size(min=4, max=5)
    private String protocol;

	@NotNull
	@NotEmpty
	@Size(min=1, max=255)
    private String host;

	@NotNull
	@Min(value=1)
	@Max(value=65535)
	@Positive
    private Integer port;
}
