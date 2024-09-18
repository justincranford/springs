package com.github.justincranford.springs.persistenceorm.base.config;

import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import com.github.justincranford.springs.util.basic.DateTimeUtil;

@Configuration
@EnableJpaAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
public class SpringsPersistenceOrmBaseJpaAuditingConfiguration {
	@SuppressWarnings("static-method")
	@Bean(name = "auditingDateTimeProvider")
	public DateTimeProvider dateTimeProvider() {
		return () -> Optional.of(DateTimeUtil.nowUtcTruncatedToMicroseconds());
	}
}
