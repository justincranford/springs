package com.github.justincranford.springs.util.testcontainers.containers;

import org.testcontainers.containers.GenericContainer;

public abstract class AbstractTestContainer<GENERIC_CONTAINER extends GenericContainer<?>> {
	protected boolean initialized;
    protected GENERIC_CONTAINER instance;

	protected abstract void initializeIfRequired();

    public abstract String getContainerName();
	public abstract GENERIC_CONTAINER getInstance();
}
