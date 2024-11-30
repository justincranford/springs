package com.github.justincranford.springs.util.testcontainers.bootstrap;

import com.github.justincranford.springs.util.basic.EnumUtils;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.Properties.ENABLE;
import com.google.common.collect.Lists;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
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

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
@SuppressWarnings({"static-method", "checkstyle:UtilityClass", "unchecked"})
public final class BootstrapTestContainers {
	static void bootstrap(final ConfigurableEnvironment configurableEnvironment) {
		try {
			final MutablePropertySources readWritePropertySources = configurableEnvironment.getPropertySources();

			final Properties properties = Properties.read(readWritePropertySources);
			final ENABLE containersEnabled = properties.enabled();
			final Map<String,String> containerEntries  = properties.containers();
			log.info("Bootstrap TestContainers Config, {}: {}, {}*: {}", Properties.ENABLED, containersEnabled, Properties.CONTAINERS_PREFIX, containerEntries);
			if (ENABLE.FALSE.equals(containersEnabled)) {
				return;
			}
			final List<ContainerDescriptor> containerDescriptors = containerEntries.entrySet().stream().map(containerEntry -> {
				final String         aliasWithoutPrefix = containerEntry.getKey().replace(Properties.CONTAINERS_PREFIX, "");
				final String         imageWithTag       = containerEntry.getValue();
				final SupportedImage supportedImage     = SupportedImage.MAP.get(imageWithTag(imageWithTag));
				if (supportedImage == null) {
					throw new RuntimeException("Image not supported for: " + aliasWithoutPrefix + ". Supported: " + SupportedImage.MAP.keySet());
				}
				final GenericContainer<?> containerInstance = createContainerInstance(aliasWithoutPrefix, supportedImage, imageWithTag);
				return new ContainerDescriptor(aliasWithoutPrefix, supportedImage, imageWithTag, containerInstance);
			}).toList();

			final List<CompletableFuture<ContainerDescriptor>> starting = containerDescriptors.stream().map(containerDescriptor ->
				CompletableFuture.supplyAsync(() -> {
					final SupportedImage      supportedImage    = containerDescriptor.supportedImage();
					final GenericContainer<?> containerInstance = containerDescriptor.containerInstance();
					containerInstance.withExposedPorts(supportedImage.exposedPorts().toArray(new Integer[0]));
					containerInstance.start();
					final String clientPropertiesString = supportedImage.clientProperties().apply(containerDescriptor).toString().replace("{", "\n{\n  ").replace("}", "\n}").replaceAll(",", ",\n ");
					final String automationDetailsString = supportedImage.toString().replace("[", "\n[\n  ").replace("]", "\n]").replace(",", ",\n ");
					log.info("\ncontainer running: {}\ncontainer alias: {}\ncontainer image: {}\ncontainer id: {}\ncontainer name: {}\nspring client properties: {}\nautomation details: {}", containerInstance.isRunning(), containerDescriptor.alias(), containerDescriptor.imageWithTag(), containerInstance.getContainerId(), containerInstance.getContainerName(), clientPropertiesString, automationDetailsString);
					Runtime.getRuntime().addShutdownHook(new Thread(containerInstance::stop));
					return containerDescriptor;
            	})
			).toList();

			final List<ContainerDescriptor> started = starting.stream().map(startingContainerDescriptor -> {
                try {
                    return startingContainerDescriptor.get();
                } catch (InterruptedException|ExecutionException e) {
					final Exception e1 = dockerRteOrOriginal(e);
					if (ENABLE.PREFERRED.equals(containersEnabled)) {
						log.warn("Failed to start container, but not fatal", e1);
						return null;
					}
					log.error("Failed to start container", e1);
					throw new RuntimeException(e);
                }
            }).toList();

			final List<MapPropertySource> propertySources = started.stream().filter(Objects::nonNull).map(containerDescriptor ->
				 new MapPropertySource(Properties.CONTAINERS + "-" + containerDescriptor.alias(), containerDescriptor.supportedImage().clientProperties().apply(containerDescriptor))
			).toList();

			if (!propertySources.isEmpty()) {
				propertySources.reversed().forEach(readWritePropertySources::addFirst);
				readWritePropertySources.addFirst(new MapPropertySource(Properties.CONTAINERS, Map.of(Properties.CONTAINERS, containerDescriptors)));
			}
		} catch(RuntimeException rte) {
			throw rte;
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static Exception dockerRteOrOriginal(final Exception e) {
		if (e.getCause() instanceof RuntimeException rte) {
			if (rte.getMessage().startsWith("Could not find a valid Docker environment.") ||
				rte.getMessage().startsWith("Previous attempts to find a Docker environment failed. Will not retry.")) {
				return rte;
			}
		}
		return e;
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

	public record ContainerDescriptor(String alias, SupportedImage supportedImage, String imageWithTag, GenericContainer<?> containerInstance) { }

	public record SupportedImage(
		Class<? extends GenericContainer<?>> containerClass, String dockerRegistry, String image, List<Integer> exposedPorts, Function<ContainerDescriptor, Map<String,Object>> clientProperties
	) {
		public static final SupportedImage POSTGRESQL = new BootstrapTestContainers.SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) PostgreSQLContainer.class,
			"docker.io", "postgres", List.of(5432),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				final PostgreSQLContainer<?> containerInstance = (PostgreSQLContainer<?>) containerDescriptor.containerInstance();
				put("spring.jpa.properties.hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
				put("spring.datasource.url",                    containerInstance.getJdbcUrl());
				put("spring.datasource.username",               containerInstance.getUsername());
				put("spring.datasource.password",               containerInstance.getPassword());
			}}
		);
		public static final SupportedImage REDIS = new SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
		   "docker.io", "redis", List.of(6379),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("spring.redis.host", containerDescriptor.containerInstance().getHost());
				put("spring.redis.port", containerDescriptor.containerInstance().getMappedPort(6379));
			}}
		);
		@SuppressFBWarnings("CT_CONSTRUCTOR_THROW")
		public static final SupportedImage ELASTICSEARCH = new SupportedImage(ElasticsearchContainer.class, // TODO Test properties with Spring Data Elasticsearch latest client
			"docker.elastic.co", "elasticsearch/elasticsearch", List.of(9200, 9300),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				final ElasticsearchContainer containerInstance = (ElasticsearchContainer) containerDescriptor.containerInstance();
				final byte[] caCertPemBytes = containerInstance.caCertAsBytes().orElseThrow(() -> new RuntimeException("Failed to read CA Cert PEM file bytes from Elasticsearch containers"));
				final String caCertPem      = new String(caCertPemBytes, StandardCharsets.UTF_8);
				put("spring.data.elasticsearch.username",                                                "elastic"); // Elasticsearch 8.0+ Security-On-By-Default username
				put("spring.data.elasticsearch.password",                                                ElasticsearchContainer.ELASTICSEARCH_DEFAULT_PASSWORD);
				put("spring.data.elasticsearch.cluster-name",                                            "elasticsearch");
				put("spring.data.elasticsearch.cluster-nodes",                                           containerInstance.getHttpHostAddress()); // AKA Mapped port for localhost:9200
				put("spring.data.elasticsearch.transport.nodes",                                         containerInstance.getHost() + ":" + containerInstance.getMappedPort(9300));
				put("spring.data.elasticsearch.rest.ssl.enabled",                                        true);
				put("spring.data.elasticsearch.rest.ssl.bundle",                                         "elasticsearch-sslbundle");
				put("spring.data.elasticsearch.rest.ssl.elasticsearch-sslbundle.truststore.certificate", caCertPem);
			}}
		);
		public static final SupportedImage KEYCLOAK = new SupportedImage(KeycloakContainer.class,
			"quay.io", "keycloak/keycloak", List.of(8080, 8443, 8787, 9000),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("keycloak.host",       containerDescriptor.containerInstance().getHost());
				put("keycloak.http.port",  containerDescriptor.containerInstance().getMappedPort(8080));
				put("keycloak.https.port", containerDescriptor.containerInstance().getMappedPort(8443));
				put("keycloak.debug.port", containerDescriptor.containerInstance().getMappedPort(8787));
				put("keycloak.mgmt.port",  containerDescriptor.containerInstance().getMappedPort(9000));
			}}
		);
		public static final SupportedImage OLLAMA = new SupportedImage(OllamaContainer.class,
			"docker.io", "ollama/ollama", List.of(11434),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("springs.service.chatbot.protocol", "http");
				put("springs.service.chatbot.host", containerDescriptor.containerInstance().getHost());
				put("springs.service.chatbot.port", containerDescriptor.containerInstance().getMappedPort(11434));
			}}
		);
		public static final SupportedImage ZIPKIN = new SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			"docker.io", "openzipkin/zipkin", List.of(9411),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("zipkin.host", containerDescriptor.containerInstance().getHost());
				put("zipkin.port", containerDescriptor.containerInstance().getMappedPort(9411));
			}}
		);
		public static final SupportedImage VAULT = new SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) VaultContainer.class,
			"docker.io", "hashicorp/vault", List.of(8200),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("vault.host", containerDescriptor.containerInstance().getHost());
				put("vault.port", containerDescriptor.containerInstance().getMappedPort(8200));
			}}
		);
		public static final SupportedImage CONSUL = new SupportedImage((Class<? extends GenericContainer<?>>) ConsulContainer.class,
			"docker.io", "hashicorp/consul", List.of(8500, 8502),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("consul.http.host",  containerDescriptor.containerInstance().getHost());
				put("consul.http.port",  containerDescriptor.containerInstance().getMappedPort(8500));
				put("consul.https.host", containerDescriptor.containerInstance().getHost());
				put("consul.https.port", containerDescriptor.containerInstance().getMappedPort(8502));
			}}
		);
		@SuppressWarnings({"deprecation"})
		public static final SupportedImage KAFKA = new SupportedImage((Class<? extends GenericContainer<?>>) KafkaContainer.class,
			"docker.io", "confluentinc/cp-kafka", List.of(9093, 2181),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("kafka.host",     containerDescriptor.containerInstance().getHost());
				put("kafka.port",     containerDescriptor.containerInstance().getMappedPort(9093));
				put("zookeeper.host", containerDescriptor.containerInstance().getHost());
				put("zookeeper.port", containerDescriptor.containerInstance().getMappedPort(2181));
			}}
		);
		public static final SupportedImage DYNAMODB = new SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			"docker.io", "amazon/dynamodb-local", List.of(8000),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("dynamodb.host", containerDescriptor.containerInstance().getHost());
				put("dynamodb.port", containerDescriptor.containerInstance().getMappedPort(8000));
			}}
		);
		public static final SupportedImage MONGODB = new SupportedImage((Class<? extends GenericContainer<?>>) MongoDBContainer.class,
			"docker.io", "mongo", List.of(27017),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("mongo.host", containerDescriptor.containerInstance().getHost());
				put("mongo.port", containerDescriptor.containerInstance().getMappedPort(27017));
			}}
		);
		public static final SupportedImage GRAFANA = new SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) GenericContainer.class,
			"docker.io", "grafana/otel-lgtm", List.of(3000, 4317, 4318, 9090),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("grafana.host", containerDescriptor.containerInstance().getHost());
				put("grafana.port", containerDescriptor.containerInstance().getMappedPort(3000));
				put("otlp.grpc.host", containerDescriptor.containerInstance().getHost());
				put("otlp.grpc.port", containerDescriptor.containerInstance().getMappedPort(4317));
				put("otlp.http.host", containerDescriptor.containerInstance().getHost());
				put("otlp.http.port", containerDescriptor.containerInstance().getMappedPort(4318));
				put("prometheus.host", containerDescriptor.containerInstance().getHost());
				put("prometheus.port", containerDescriptor.containerInstance().getMappedPort(9090));
			}}
		);
		public static final SupportedImage SELENIUMCHROME = new SupportedImage((Class<? extends GenericContainer<?>>) (Class<?>) BrowserWebDriverContainer.class,
			"docker.io", "selenium/standalone-chrome", List.of(4444, 5900),
			(containerDescriptor) -> new LinkedHashMap<>() {{
				put("selenium.host", containerDescriptor.containerInstance().getHost());
				put("selenium.port", containerDescriptor.containerInstance().getMappedPort(4444));
				put("vnc.host",      containerDescriptor.containerInstance().getHost());
				put("vnc.port",      containerDescriptor.containerInstance().getMappedPort(5900));
			}}
		);

		public static final List<SupportedImage> LIST = List.of(
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

		public static final Map<String,SupportedImage> MAP = LIST.stream()
																 .flatMap(descriptor -> Stream.of(
			    new AbstractMap.SimpleEntry<>(descriptor.image(), descriptor),
			    new AbstractMap.SimpleEntry<>(descriptor.dockerRegistry() + "/" + descriptor.image(), descriptor)
		    ))
																 .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));
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

	public static @Nullable List<ContainerDescriptor> find(final Environment environment, final String image) {
		@SuppressWarnings({"unchecked"})
		final List<ContainerDescriptor> containerDescriptors = environment.getProperty(Properties.CONTAINERS, List.class);
		if (containerDescriptors == null) {
			log.info("List of ContainerDescriptors is null");
			return null;
		}
		final List<ContainerDescriptor> foundContainerDescriptors = containerDescriptors.stream().filter(containerDescriptor -> containerDescriptor.supportedImage().image().contains(image)).toList();
		if (foundContainerDescriptors.isEmpty()) {
			log.info("List of ContainerDescriptors does not have any matches");
			return null;
		}
		log.info("Found ContainerDescriptors: {}", foundContainerDescriptors);
		return foundContainerDescriptors;
	}

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

	private static @NotNull String imageWithTag(final String imageWithTag) {
		return imageWithTag.contains(":") ? imageWithTag.substring(0, imageWithTag.lastIndexOf(':')) : imageWithTag;
	}

	private static GenericContainer<?> createContainerInstance(final String aliasWithoutPrefix, final SupportedImage supportedImage, final String imageWithTag) {
		try {
			final Constructor<? extends GenericContainer<?>> constructorDockerImageName = supportedImage.containerClass().getConstructor(DockerImageName.class);
			final DockerImageName dockerImageName = DockerImageName.parse(imageWithTag);
			return constructorDockerImageName.newInstance(dockerImageName); // KafkaContainer(String) incorrectly expects version
		} catch(Exception e1) {
			try {
				final Constructor<? extends GenericContainer<?>> constructorString = supportedImage.containerClass().getConstructor(String.class);
				return constructorString.newInstance(imageWithTag); // Keycloak(DockerImageName) is missing, fall back to KafkaContainer(String)
			} catch(Exception e2) {
				final RuntimeException rte = new RuntimeException("Error creating container for: " + aliasWithoutPrefix);
				rte.addSuppressed(e1);
				rte.addSuppressed(e2);
				throw rte;
			}
		}
	}
}
