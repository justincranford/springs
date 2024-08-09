package com.github.justincranford.springs.util.basic;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StaticBeanUtil implements ApplicationContextAware {
	private static ApplicationContext APPLICATION_CONTEXT;

	public static <BEAN> BEAN get(final Class<BEAN> clazz) {
		return APPLICATION_CONTEXT.getBean(clazz);
	}

	@Override
	public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
		APPLICATION_CONTEXT = applicationContext;
	}
}
