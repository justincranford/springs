package com.github.justincranford.springs.util.testcontainers.containers;

import org.testcontainers.containers.GenericContainer;

public abstract class AbstractTestContainer<GENERIC_CONTAINER extends GenericContainer<?>> {
    public abstract String getContainerName();
	public abstract GENERIC_CONTAINER initAndGetInstance();

    public GENERIC_CONTAINER instance;
	public GENERIC_CONTAINER getInstance() {
		return this.instance;
	}

	public boolean isRunning() {
		return (this.instance != null) && this.instance.isRunning();
	}
}
