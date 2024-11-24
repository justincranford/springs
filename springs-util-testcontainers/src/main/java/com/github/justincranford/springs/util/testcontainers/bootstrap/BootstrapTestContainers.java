package com.github.justincranford.springs.util.testcontainers.bootstrap;

import com.github.justincranford.springs.util.basic.EnumUtils;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.Properties.ENABLE;
import com.google.common.collect.Lists;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
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
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
@SuppressWarnings({"static-method", "checkstyle:UtilityClass", "unchecked"})
public final class BootstrapTestContainers {
	public static List<ContainerDescriptor> running(final Environment environment, final String image) {
		final List<ContainerDescriptor> foundContainerDescriptors = find(environment, image);
		if (foundContainerDescriptors == null) {
			return null;
		}
		final List<ContainerDescriptor> runningContainerDescriptors = foundContainerDescriptors.stream().filter(containerDescriptor -> containerDescriptor.containerInstance().isRunning()).toList();
		if (runningContainerDescriptors.isEmpty()) {
			log.info("List of found ContainerDescriptors does not have any running");
			return null;
		}
		log.info("Running ContainerDescriptors: {}", runningContainerDescriptors);
		return runningContainerDescriptors;
	}

	public static @Nullable List<ContainerDescriptor> find(final Environment environment, final String image) {
		@SuppressWarnings({"unchecked"})
		final List<ContainerDescriptor> containerDescriptors = environment.getProperty(Properties.CONTAINERS, List.class);
		if (containerDescriptors == null) {
			log.info("List of ContainerDescriptors is null");
			return null;
		}
		final List<ContainerDescriptor> foundContainerDescriptors = containerDescriptors.stream().filter(containerDescriptor -> containerDescriptor.imageDescriptor().image().contains(image)).toList();
		if (foundContainerDescriptors.isEmpty()) {
			log.info("List of ContainerDescriptors does not have any matches");
			return null;
		}
		log.info("Found ContainerDescriptors: {}", foundContainerDescriptors);
		return foundContainerDescriptors;
	}

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
					final String          alias           = containerDescriptorEntry.getKey().replace(Properties.CONTAINERS_PREFIX, "");
					final String          imageWithTag    = containerDescriptorEntry.getValue();
					final String          imageWithoutTag = imageWithTag.contains(":") ? imageWithTag.substring(0, imageWithTag.lastIndexOf(':')) : imageWithTag;
					final ImageDescriptor imageDescriptor = ImageDescriptor.MAP.get(imageWithoutTag);
					if (imageDescriptor == null) {
						throw new RuntimeException("ImageDescription not found for: " + containerDescriptorEntry.getKey() + ". Valid: " + ImageDescriptor.MAP.keySet());
					}
					GenericContainer<?> containerInstance;
					try {
						final DockerImageName dockerImageName = DockerImageName.parse(imageWithTag);
						containerInstance = imageDescriptor.containerClass().getConstructor(DockerImageName.class).newInstance(dockerImageName); // KafkaContainer(String) incorrectly expects version
					} catch(Exception e1) {
						try {
							containerInstance = imageDescriptor.containerClass().getConstructor(String.class).newInstance(imageWithTag); // Keycloak(DockerImageName) is missing, fall back to KafkaContainer(String)
						} catch(Exception e2) {
							final RuntimeException rte = new RuntimeException("Error creating container for: " + containerDescriptorEntry.getKey());
							rte.addSuppressed(e1);
							rte.addSuppressed(e2);
							throw rte;
						}
					}
					containerDescriptors.add(new ContainerDescriptor(alias, imageDescriptor, containerInstance));
				} catch(RuntimeException rte) {
					throw rte;
				} catch (Exception e) {
					throw new RuntimeException("Error creating container for: " + containerDescriptorEntry.getKey(), e);
				}
			}

			final List<CompletableFuture<ContainerDescriptor>> futures = new ArrayList<>();
			for (final ContainerDescriptor containerDescriptor : containerDescriptors) {
				futures.add(CompletableFuture.supplyAsync(() -> {
					final String              alias               = containerDescriptor.alias();
					final ImageDescriptor     imageDescriptor     = containerDescriptor.imageDescriptor();
					final GenericContainer<?> containerInstance   = containerDescriptor.containerInstance();
					containerInstance.withExposedPorts(imageDescriptor.exposedPorts().toArray(new Integer[0]));
					containerInstance.start();
					final Map<String,Object> clientProperties = containerDescriptor.clientProperties(); // apply container mapped ports and additional settings to client properties
					log.info("alias: {}, isRunning: {}, properties: {}, imageDescriptor: {}, id: {}, name: {}", alias, containerInstance.isRunning(), clientProperties, imageDescriptor, containerInstance.getContainerId(), containerInstance.getContainerName());
					Runtime.getRuntime().addShutdownHook(new Thread(containerInstance::stop));
					return containerDescriptor;
				}));
			}
			final List<MapPropertySource> propertySources = new ArrayList<>();
			for (final CompletableFuture<ContainerDescriptor> future : futures) {
				final ContainerDescriptor containerDescriptor = future.get();
				propertySources.add(new MapPropertySource(Properties.CONTAINERS + "-" + containerDescriptor.alias(), containerDescriptor.clientProperties()));
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

	public record ContainerDescriptor(String alias, ImageDescriptor imageDescriptor, GenericContainer<?> containerInstance) {
		private Map<String,Object> clientProperties() {
			final Map<String,Object> clientProperties = new LinkedHashMap<>(this.imageDescriptor.clientProperties());
			this.imageDescriptor.clientProperties().forEach((key, value) -> {
				if ((value instanceof Integer exposedPort) && (this.imageDescriptor.exposedPorts().contains(exposedPort))) {
					clientProperties.put(key, this.containerInstance().getMappedPort(exposedPort));
				}
			});
			this.imageDescriptor.appendExtraClientProperties().accept(this, clientProperties);
			return clientProperties;
		}
	}

	public record ImageDescriptor(
		Class<? extends GenericContainer<?>> containerClass, String dockerRegistry, String image, List<Integer> exposedPorts, Map<String,Object> clientProperties, BiConsumer<ContainerDescriptor, Map<String,Object>> appendExtraClientProperties
	) {
		public static final ImageDescriptor REDIS = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			"docker.io", "redis", List.of(6379),
			new LinkedHashMap<>() {{
				put("spring.redis.host", "localhost");
				put("spring.redis.port", 6379);
			}},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor ELASTICSEARCH = new ImageDescriptor(ElasticsearchContainer.class,
			"docker.elastic.co", "elasticsearch/elasticsearch", List.of(9200, 9300),
			new LinkedHashMap<>() {{
				put("elasticsearch.host", "localhost");
				put("elasticsearch.port", 9200);
				put("elasticsearch.transport.host", "localhost");
				put("elasticsearch.transport.port", 9300);
			}},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor KEYCLOAK = new ImageDescriptor(KeycloakContainer.class,
			"quay.io", "keycloak/keycloak", List.of(8080, 8443, 8787, 9000), new LinkedHashMap<>() {{
				put("keycloak.host",       "localhost");
				put("keycloak.http.port",  8080);
				put("keycloak.https.port", 8443);
				put("keycloak.debug.port", 8787);
				put("keycloak.mgmt.port",  9000);
			}},
		   (containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor POSTGRESQL = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) PostgreSQLContainer.class,
			 "docker.io", "postgres", List.of(5432),
			 new LinkedHashMap<>() {{
				put("postgres.host",                           "localhost");
				put("postgres.port",                           5432);
				put("spring.jpa.properties.hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
			 }},
			(containerDescriptor, clientProperties) -> {
				final PostgreSQLContainer<?> containerInstance = (PostgreSQLContainer<?>) containerDescriptor.containerInstance();
				clientProperties.put("spring.datasource.url",      containerInstance.getJdbcUrl());
				clientProperties.put("spring.datasource.username", containerInstance.getUsername());
				clientProperties.put("spring.datasource.password", containerInstance.getPassword());
			}
		);
		public static final ImageDescriptor OLLAMA = new ImageDescriptor(OllamaContainer.class,
	        "docker.io", "ollama/ollama", List.of(11434), new LinkedHashMap<>() {{
				put("springs.service.chatbot.protocol", "http");
				put("springs.service.chatbot.host", "localhost");
				put("springs.service.chatbot.port", 11434);
			}},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor ZIPKIN = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
    	    "docker.io", "openzipkin/zipkin", List.of(9411), new LinkedHashMap<>() {{
				 put("zipkin.host", "localhost");
				 put("zipkin.port", 9411);
			 }},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor VAULT = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) VaultContainer.class,
        	"docker.io", "hashicorp/vault", List.of(8200), new LinkedHashMap<>() {{
				 put("vault.host", "localhost");
				 put("vault.port", 8200);
			}},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor CONSUL = new ImageDescriptor((Class<? extends GenericContainer<?>>) ConsulContainer.class,
	        "docker.io", "hashicorp/consul", List.of(8500, 8502), new LinkedHashMap<>() {{
				put("consul.http.host", "localhost");
				put("consul.http.port", 8500);
				put("consul.https.host", "localhost");
				put("consul.https.port", 8502);
			}},
			(containerDescriptor, clientProperties) -> {}
		);
		@SuppressWarnings({"deprecation"})
		public static final ImageDescriptor KAFKA = new ImageDescriptor((Class<? extends GenericContainer<?>>) KafkaContainer.class,
    	    "docker.io", "confluentinc/cp-kafka", List.of(9093, 2181),
			new LinkedHashMap<>() {{
				 put("kafka.host", "localhost");
				 put("kafka.port", 9093);
				 put("zookeeper.host", "localhost");
				 put("zookeeper.port", 2181);
			 }},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor DYNAMODB = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
	 	  "docker.io", "amazon/dynamodb-local", List.of(8000),
		   new LinkedHashMap<>() {{
				put("dynamodb.host", "localhost");
				put("dynamodb.port", 8000);
			}},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor MONGODB = new ImageDescriptor((Class<? extends GenericContainer<?>>) MongoDBContainer.class,
			"docker.io", "mongo", List.of(27017),
			new LinkedHashMap<>() {{
			   put("mongo.host", "localhost");
			   put("mongo.port", 27017);
		   }},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor GRAFANA = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
		  "docker.io", "grafana/otel-lgtm", List.of(3000, 4317, 4318, 9090),
		  new LinkedHashMap<>() {{
			   put("grafana.host", "localhost");
			   put("grafana.port", 3000);
			   put("otlp.grpc.host", "localhost");
			   put("otlp.grpc.port", 4317);
			   put("otlp.http.host", "localhost");
			   put("otlp.http.port", 4318);
			   put("prometheus.host", "localhost");
			   put("prometheus.port", 9090);
		   }},
			(containerDescriptor, clientProperties) -> {}
		);
		public static final ImageDescriptor SELENIUMCHROME = new ImageDescriptor((Class<? extends GenericContainer<?>>) (Class<?>) BrowserWebDriverContainer.class,
			"docker.io", "selenium/standalone-chrome", List.of(4444, 5900),
			 new LinkedHashMap<>() {{
			   put("selenium.host", "localhost");
			   put("selenium.port", 4444);
			   put("vnc.host",      "localhost");
			   put("vnc.port",      5900);
			}},
			(containerDescriptor, clientProperties) -> {}
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
