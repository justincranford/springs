package com.github.justincranford.springs.util.security.passwords.config;

import com.github.justincranford.springs.util.security.passwords.generator.PasswordGeneratorConfiguration;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
    basePackageClasses = { SpringsUtilSecurityPasswordsProperties.class }
)
@Import(
    value = { PasswordGeneratorConfiguration.class }
)
public class SpringsUtilSecurityPasswordsConfiguration {
    // do nothing
}
