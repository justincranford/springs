package com.github.justincranford.springs.util.observability.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.util.observability.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings("static-method")
public class StaticBeanUtilTest extends AbstractIT {
	@Test
	void testComponentBean1() {
		assertThat(StaticBeanUtil.get(Bean1.class)).isInstanceOf(Bean1.class);
	}

	@Test
	void testConfigurationBean2() {
		assertThat(StaticBeanUtil.get(Bean2.class)).isInstanceOf(Bean2.class);
	}

	@Component
	public static class Bean1 {
		// do nothing
    }

    @Bean
	public Bean2 bean2() {
		return new Bean2();
	}

    public static class Bean2 {
		// do nothing
	}
}
