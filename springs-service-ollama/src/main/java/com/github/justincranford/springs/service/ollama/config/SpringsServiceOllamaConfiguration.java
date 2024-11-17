package com.github.justincranford.springs.service.ollama.config;

import com.github.justincranford.springs.service.ollama.config.client.OllamaClientConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import org.springframework.ai.autoconfigure.ollama.OllamaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableConfigurationProperties
@Import({
    SpringsUtilJsonConfiguration.class,
    OllamaAutoConfiguration.class,
    OllamaClientConfiguration.class
})
public class SpringsServiceOllamaConfiguration {
    // do nothing
}
