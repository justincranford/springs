package com.github.justincranford.springs.persistenceorm.base.config;

import com.github.justincranford.springs.util.basic.DateTimeUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.util.Optional;

@Configuration
@EnableJpaAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
@SuppressWarnings({ "unused" })
public class SpringsPersistenceOrmBaseJpaAuditingConfiguration {
    @SuppressWarnings("static-method")
    @Bean(name = "auditingDateTimeProvider")
    public DateTimeProvider dateTimeProvider() {
        return () -> Optional.of(DateTimeUtil.nowUtcTruncatedToMicroseconds());
    }
}
