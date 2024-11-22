package com.github.justincranford.springs.util.testcontainers.bootstrap;

import com.github.justincranford.springs.util.basic.EnumUtils;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.Properties.ENABLE;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.validation.metadata.ContainerDescriptor;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.env.OriginTrackedMapPropertySource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.PropertySources;
import org.testcontainers.consul.ConsulContainer;
import org.testcontainers.containers.BrowserWebDriverContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.elasticsearch.ElasticsearchContainer;
import org.testcontainers.ollama.OllamaContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
@SuppressWarnings({"static-method", "checkstyle:UtilityClass", "unchecked"})
public final class BootstrapTestContainers {
	public static List<ContainerDescriptor> cleanup(final ConfigurableEnvironment environment1) {
		final List<ContainerDescriptor> containerDescriptors = environment1.getProperty(BootstrapTestContainers.Properties.CONTAINERS, List.class);
		if (containerDescriptors != null) {
			for (final ContainerDescriptor containerDescriptor : containerDescriptors) {
				containerDescriptor.containerInstance().stop();
			}
		}
		return containerDescriptors;
	}

	static void bootstrap(final ConfigurableEnvironment configurableEnvironment) {
		ENABLE enabled = Properties.ENABLED_DEFAULT;
		try {
			final MutablePropertySources readWritePropertySources = configurableEnvironment.getPropertySources();

            final Properties         properties = Properties.read(readWritePropertySources);
			                         enabled    = properties.enabled();
			final Map<String,String> containers = properties.containers();
			log.info("Bootstrap TestContainers Config, {}: {}, {}*: {}", Properties.ENABLED, enabled,  Properties.CONTAINERS_PREFIX, containers);
			if (ENABLE.FALSE.equals(enabled)) {
				return;
			}

			final List<ContainerDescriptor> containerDescriptors = new ArrayList<>();
			for (final Entry<String,String> containerDescriptorEntry : containers.entrySet()) {
				try {
					final String                               alias               = containerDescriptorEntry.getKey().replace(Properties.CONTAINERS_PREFIX, "");
					final String                               image               = containerDescriptorEntry.getValue();
					final String                               imageWithoutTag     = image.contains(":") ? image.substring(0, image.lastIndexOf(':')) : image;
					final ImageDescriptor                      imageDescriptor     = ImageDescriptor.MAP.get(imageWithoutTag);
					if (imageDescriptor == null) {
						throw new RuntimeException("ImageDescription not found for: " + containerDescriptorEntry.getKey() + ". Valid: " + ImageDescriptor.MAP.keySet());
					}
					final Class<? extends GenericContainer<?>> containerClass      = imageDescriptor.containerClass();
					final Map<String,String>                   containerProperties = imageDescriptor.containerProperties();
					final Consumer<ContainerDescriptor>        updateProperties    = imageDescriptor.updateProperties();
					GenericContainer<?> containerInstance;
					try {
						final DockerImageName dockerImageName = DockerImageName.parse(image);
						containerInstance = containerClass.getConstructor(DockerImageName.class).newInstance(dockerImageName); // KafkaContainer(String) incorrectly expects version
					} catch(Exception e1) {
						throw e1;
//						try {
//							containerInstance = containerClass.getConstructor(String.class).newInstance(image);
//						} catch(Exception e2) {
//							e1.addSuppressed(e2);
//							throw e1;
//						}
					}
					containerDescriptors.add(new ContainerDescriptor(alias, image, containerProperties, containerInstance, updateProperties));
				} catch(RuntimeException rte) {
					throw rte;
				} catch (Exception e) {
					throw new RuntimeException("Error creating container for: " + containerDescriptorEntry.getKey(), e);
				}
			}

			final List<CompletableFuture<ContainerDescriptor>> futures = new ArrayList<>();
			for (final ContainerDescriptor containerDescriptor : containerDescriptors) {
				futures.add(CompletableFuture.supplyAsync(() -> {
					final Map<String, Integer> exposedPorts = containerDescriptor.exposedPorts();
					final GenericContainer<?> containerInstance = containerDescriptor.containerInstance();
//					containerInstance.withReuse(true);
					containerInstance.withExposedPorts(exposedPorts.values().toArray(new Integer[0]));
					containerInstance.start();
					containerDescriptor.updateProperties().accept(containerDescriptor);
					final Map<String, Integer> mappedPorts = containerDescriptor.mappedPorts();
					log.info("alias: {}, image: {}, isRunning: {}, properties: {}, exposedPorts: {}. mappedPorts: {}, id: {}, name: {}", containerDescriptor.alias(), containerDescriptor.image(), containerInstance.isRunning(), containerDescriptor.containerProperties(), exposedPorts, mappedPorts, containerInstance.getContainerId(), containerInstance.getContainerName());
					Runtime.getRuntime().addShutdownHook(new Thread(containerInstance::stop));
					return containerDescriptor;
				}));
			}
			final List<MapPropertySource> propertySources = new ArrayList<>();
			for (final CompletableFuture<ContainerDescriptor> future : futures) {
				final ContainerDescriptor containerDescriptor = future.get();
				final String containerAlias = containerDescriptor.image();
				final Map<String, Object> containerProperties = new LinkedHashMap<>((Map) containerDescriptor.containerProperties());
				containerProperties.putAll(containerDescriptor.mappedPorts()); // overwrite properties to change them from exposedPorts to mappedPorts
				log.info("Prepending containerProperties: {}", containerProperties);
				propertySources.add(new MapPropertySource(Properties.CONTAINERS + "-" + containerAlias, containerProperties));
			}
			for (final MapPropertySource propertySource : propertySources.reversed()) {
				readWritePropertySources.addFirst(propertySource);
			}
			readWritePropertySources.addFirst(new MapPropertySource(Properties.CONTAINERS, Map.of(Properties.CONTAINERS, containerDescriptors)));
		} catch(RuntimeException rte) {
			throw rte;
		} catch(ExecutionException e) {
			if (ENABLE.PREFERRED.equals(enabled)) {
				log.warn("Failed to start container", e);
				return;
			}
			log.error("Failed to start container", e);
			if (e.getCause() instanceof RuntimeException re) {
				if (re.getMessage().startsWith("Could not find a valid Docker environment.") ||
					re.getMessage().startsWith("Previous attempts to find a Docker environment failed. Will not retry.")) {
					throw re;
				}

			}
			throw new RuntimeException(e);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings({"unused"})
	public record Properties(ENABLE enabled, Map<String,String> containers) {
		public enum                ENABLE { TRUE, PREFERRED, FALSE }
		public static final String ENABLED            = "bootstrap.testcontainers.enabled";
		public static final ENABLE ENABLED_DEFAULT    = ENABLE.FALSE;
		public static final String CONTAINERS         = "bootstrap.testcontainers.containers";
		public static final String CONTAINERS_PREFIX  = CONTAINERS + ".";

		private static Properties read(final PropertySources propertySources) {
			final Map<String, String> found = new HashMap<>();
			for (final PropertySource<?> propertySource : Lists.newArrayList(propertySources.iterator())) {
				if (propertySource.containsProperty(ENABLED)) {
					found.putIfAbsent(ENABLED, Objects.requireNonNull(propertySource.getProperty(ENABLED)).toString());
				}
				if (propertySource instanceof org.springframework.core.env.MapPropertySource mapPropertySource) {
					for (final String key : mapPropertySource.getPropertyNames()) {
						if (key.startsWith(CONTAINERS_PREFIX)) {
							found.putIfAbsent(key, Objects.requireNonNull(propertySource.getProperty(key)).toString());
						}
					}
				}
			}
			final ENABLE enabled = EnumUtils.valueOfCaseInsensitive(ENABLE.class, found.getOrDefault(ENABLED, ENABLED_DEFAULT.name())) ;
			found.remove(ENABLED);
			return new Properties(enabled, found);
		}
	}

	public record ContainerDescriptor(String alias, String image, Map<String, String> containerProperties, GenericContainer<?> containerInstance, Consumer<ContainerDescriptor> updateProperties) {
		private Map<String,Integer> exposedPorts() {
			final Map<String,Integer> exposedPorts = new LinkedHashMap<>();
			this.containerProperties.forEach((key, value) -> {
				if (key.endsWith(".port")) {
					final int originalPort = Integer.parseInt(value);
					exposedPorts.put(key, originalPort);
				}
			});
			return exposedPorts;
		}

		private Map<String,Integer> mappedPorts() {
			final Map<String,Integer> mappedPorts = new LinkedHashMap<>();
			exposedPorts().forEach((key, value) -> {
				final int mappedPort = this.containerInstance().getMappedPort(value);
				mappedPorts.put(key, mappedPort);
			});
			return mappedPorts;
		}
	}

	@VisibleForTesting
	public static void insert(final MutablePropertySources mutablePropertySources) {
		final Map<String, Object> properties = new LinkedHashMap<>();
		mutablePropertySources.addFirst(new OriginTrackedMapPropertySource("auto-config-testcontainers", properties));
	}

	public record ImageDescriptor(
		Class<? extends GenericContainer<?>> containerClass, String dockerRegistry, String image, Map<String,String> containerProperties, Consumer<ContainerDescriptor> updateProperties
	) {
		public static final ImageDescriptor ELASTICSEARCH = new ImageDescriptor(ElasticsearchContainer.class,
			"docker.elastic.co", "elasticsearch/elasticsearch",
			new LinkedHashMap<>() {{
				put("elasticsearch.host", "localhost");
				put("elasticsearch.port", "9200");
				put("elasticsearch.transport.host", "localhost");
				put("elasticsearch.transport.port", "9300");
			}},
			(containerDescriptor) -> {}
		);
		public static final ImageDescriptor KEYCLOAK = new ImageDescriptor(
			KeycloakContainer.class,
			"quay.io", "keycloak/keycloak",
			new LinkedHashMap<>() {{
				put("keycloak.host",       "localhost");
				put("keycloak.http.port",  "8080");
				put("keycloak.https.port", "8443");
				put("keycloak.debug.port", "8787");
				put("keycloak.mgmt.port",  "9000");
			}},
			(containerDescriptor) -> {
				// TODO
			}
		);
		public static final ImageDescriptor POSTGRESQL = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) PostgreSQLContainer.class,
		    "docker.io", "postgres",
			 new LinkedHashMap<>() {{
				put("postgres.host",                           "localhost");
				put("postgres.port",                           "5432");
				put("spring.jpa.properties.hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
			}},
		    (containerDescriptor) -> {
				final PostgreSQLContainer<?> containerInstance = (PostgreSQLContainer<?>) containerDescriptor.containerInstance();
				containerDescriptor.containerProperties().put("spring.datasource.url",      containerInstance.getJdbcUrl());
				containerDescriptor.containerProperties().put("spring.datasource.username", containerInstance.getUsername());
				containerDescriptor.containerProperties().put("spring.datasource.password", containerInstance.getPassword());
			}
		);
		public static final ImageDescriptor REDIS = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			"docker.io", "redis",
				new LinkedHashMap<>() {{
				    put("redis.host", "localhost");
				    put("redis.port", "6379");
			    }},
				(containerDescriptor) -> {
					// TODO
				}
		);
		public static final ImageDescriptor OLLAMA = new ImageDescriptor(OllamaContainer.class,
			"docker.io", "ollama/ollama",
			new LinkedHashMap<>() {{
				put("ollama.host", "localhost");
				put("ollama.port", "11434");
			}},
			(containerDescriptor) -> {
				// TODO
			}
		);
		public static final ImageDescriptor ZIPKIN = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			 "docker.io", "openzipkin/zipkin",
			 new LinkedHashMap<>() {{
				 put("zipkin.host", "localhost");
				 put("zipkin.port", "9411");
			 }},
			 (containerDescriptor) -> {
				 // TODO
			 }
		);
		public static final ImageDescriptor VAULT = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) VaultContainer.class,
			"docker.io", "hashicorp/vault",
			new LinkedHashMap<>() {{
				 put("vault.host", "localhost");
				 put("vault.port", "8200");
			 }},
			(containerDescriptor) -> {
				// TODO
			}
		);
		public static final ImageDescriptor CONSUL = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) ConsulContainer.class,
			"docker.io", "hashicorp/consul",
			new LinkedHashMap<>() {{
				put("consul.host", "localhost");
				put("consul.port", "8500");
				put("consul2.host", "localhost");
				put("consul2.port", "8502");
			}},
			(containerDescriptor) -> {
				// TODO
			}
		);
		@SuppressWarnings({"deprecation"})
		public static final ImageDescriptor KAFKA = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) KafkaContainer.class,
			 "docker.io", "confluentinc/cp-kafka",
			 new LinkedHashMap<>() {{
				 put("kafka.host", "localhost");
				 put("kafka.port", "9093");
				 put("zookeeper.host", "localhost");
				 put("zookeeper.port", "2181");
			 }},
			 (containerDescriptor) -> {
				 // TODO
			 }
		);
		public static final ImageDescriptor DYNAMODB = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			"docker.io", "amazon/dynamodb-local",
			new LinkedHashMap<>() {{
				put("dynamodb.host", "localhost");
				put("dynamodb.port", "8000");
			}},
			(containerDescriptor) -> {
				// TODO
			}
		);
		public static final ImageDescriptor MONGODB = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) MongoDBContainer.class,
		   "docker.io", "mongo",
		   new LinkedHashMap<>() {{
			   put("mongo.host", "localhost");
			   put("mongo.port", "27017");
		   }},
		   (containerDescriptor) -> {
			   // TODO
		   }
		);
		public static final ImageDescriptor GRAFANA = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
		   "docker.io", "grafana/otel-lgtm",
		   new LinkedHashMap<>() {{
			   put("grafana.host", "localhost");
			   put("grafana.port", "3000");
			   put("otlp.grpc.host", "localhost");
			   put("otlp.grpc.port", "4317");
			   put("otlp.http.host", "localhost");
			   put("otlp.http.port", "4318");
			   put("prometheus.host", "localhost");
			   put("prometheus.port", "9090");
		   }},
		   (containerDescriptor) -> {
			   // TODO
		   }
		);
		public static final ImageDescriptor SELENIUMCHROME = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) BrowserWebDriverContainer.class,
		   "docker.io", "selenium/standalone-chrome",
		    new LinkedHashMap<>() {{
			   put("selenium.host", "localhost");
			   put("selenium.port", "4444");
			   put("vnc.host",      "localhost");
			   put("vnc.port",      "5900");
		   }},
		   (containerDescriptor) -> {
			   // TODO
		   }
		);

		public static final List<ImageDescriptor> LIST = List.of(
			ELASTICSEARCH,
			KEYCLOAK,
			POSTGRESQL,
			REDIS,
			OLLAMA,
			ZIPKIN,
			VAULT,
			CONSUL,
			KAFKA,
			DYNAMODB,
			MONGODB,
			GRAFANA,
			SELENIUMCHROME
		);

		public static final Map<String,ImageDescriptor> MAP = LIST.stream()
		    .flatMap(descriptor -> Stream.of(
			    new AbstractMap.SimpleEntry<>(descriptor.image(), descriptor),
			    new AbstractMap.SimpleEntry<>(descriptor.dockerRegistry() + "/" + descriptor.image(), descriptor)
		    ))
		    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));
	}
}
