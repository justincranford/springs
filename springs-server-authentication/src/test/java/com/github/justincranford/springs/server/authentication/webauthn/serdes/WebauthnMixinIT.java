package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.session.Session;
import org.springframework.session.SessionIdGenerator;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.SpringSessionRedisConnectionFactory;
import org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration;
import org.springframework.test.context.ActiveProfiles;
import redis.embedded.RedisServer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment=WebEnvironment.NONE)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"unused", "rawtypes"})
public class WebauthnMixinIT {
    @Autowired
    private SessionRepository redisSessionRepository;

    @Test
    public void test1() throws JsonProcessingException {
        final ObjectMapper objectMapper = newObjectMapper();
        doSerDes(objectMapper, publicKeyCredentialRequestOptions());
    }

    @Test
    @SuppressWarnings({"unchecked"})
    void testSecurityContextSerialization() {
        final UsernamePasswordAuthenticationToken expectedAuthenticationToken = UsernamePasswordAuthenticationToken.authenticated(
            "admin1", "password", List.of(new SimpleGrantedAuthority("ROLE_ADM"))
        );

        final SecurityContext expectedSecurityContext = SecurityContextHolder.createEmptyContext();
        expectedSecurityContext.setAuthentication(expectedAuthenticationToken);

        final Session session = this.redisSessionRepository.createSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, expectedSecurityContext);
        this.redisSessionRepository.save(session);

        // Retrieve SecurityContext, which implies deserialization
        final Session retrievedSession = this.redisSessionRepository.findById(session.getId());
        assertThat(retrievedSession).isNotNull();

        // Validate contents of the Session
        final Object deserializedSecurityContext = retrievedSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(deserializedSecurityContext).isInstanceOf(SecurityContext.class);
        final SecurityContext actualSecurityContext = (SecurityContext) deserializedSecurityContext;
        assertThat(actualSecurityContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);

        final UsernamePasswordAuthenticationToken actualAuthenticationToken = (UsernamePasswordAuthenticationToken) actualSecurityContext.getAuthentication();
        assertThat(actualAuthenticationToken).isEqualTo(expectedAuthenticationToken);
        assertThat(actualAuthenticationToken.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_ADM");
    }

    private static void doSerDes(final ObjectMapper objectMapper, final Object object) throws JsonProcessingException {
        final String serialized = objectMapper.writeValueAsString(object);
        log.info("Serialized: {}", serialized);
        final Object deserialized = objectMapper.readValue(serialized, PublicKeyCredentialRequestOptions.class);
        log.info("Deserialized: {}\n", deserialized);
        Assertions.assertEquals(object, deserialized);
    }

    public static class RedisConfiguration {
        @Bean(initMethod="start",destroyMethod="stop")
        public RedisServer redisServerEmbedded(final Environment environment) throws IOException {
            final RedisServer redisServer = new RedisServer(6379);
            redisServer.start();
            return redisServer;
        }

        @Bean
        public LettuceConnectionFactory redisConnectionFactory() {
            return new LettuceConnectionFactory("localhost", 6379);
        }

        @Bean
        public RedisTemplate<String, Object> sessionRedisTemplate(
            final LettuceConnectionFactory redisConnectionFactory,
            final RedisSerializer<Object> springSessionDefaultRedisSerializer
        ) {
            final StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();
            final RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
            redisTemplate.setConnectionFactory(redisConnectionFactory);
            redisTemplate.setKeySerializer(stringRedisSerializer);
            redisTemplate.setHashKeySerializer(stringRedisSerializer);
            redisTemplate.setValueSerializer(springSessionDefaultRedisSerializer);
            redisTemplate.setHashValueSerializer(springSessionDefaultRedisSerializer);
            redisTemplate.setDefaultSerializer(springSessionDefaultRedisSerializer);
            log.info("redisTemplate: {}", redisTemplate);
            return redisTemplate;
        }

        @Bean
        public RedisHttpSessionConfiguration redisHttpSessionConfiguration(
            @SpringSessionRedisConnectionFactory ObjectProvider<RedisConnectionFactory> springSessionRedisConnectionFactory,
            RedisSerializer<Object> springSessionDefaultRedisSerializer,
            final RedisConnectionFactory redisConnectionFactory
        ) {
            final RedisHttpSessionConfiguration config = new RedisHttpSessionConfiguration();
            config.setSessionIdGenerator(new CustomSessionIdGenerator());
            config.setMaxInactiveInterval(Duration.ofSeconds(7));
            config.setRedisNamespace("test");
            config.setDefaultRedisSerializer(springSessionDefaultRedisSerializer);
            final ObjectProvider<RedisConnectionFactory> objectProvider = new ObjectProvider<>() {
                @Override
                public @NotNull RedisConnectionFactory getObject() throws BeansException {
                    return redisConnectionFactory;
                }
            };
            config.setRedisConnectionFactory(objectProvider, objectProvider);
            return config;
        }

        @Bean(name="springSessionDefaultRedisSerializer")
        public RedisSerializer<Object> springSessionDefaultRedisSerializer(@Qualifier("springSessionDefaultObjectMapper") final ObjectMapper springSessionDefaultObjectMapper) {
            return GenericJackson2JsonRedisSerializer.builder().objectMapper(springSessionDefaultObjectMapper).build();
        }

        @Qualifier("springSessionDefaultObjectMapper")
        @Bean
        public ObjectMapper springSessionDefaultObjectMapper() {
            final ObjectMapper objectMapper = newObjectMapper();

            // Registers CoreJackson2Module (e.g. SimpleGrantedAuthorityMixin) and many others
            objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));

            // Relax deserialization to handle this cryptic Collections$UnmodifiableRandomAccessList nested serialization:
            //    "authorities" : [ "java.util.Collections$UnmodifiableRandomAccessList", [ {
            //      "@class" : "org.springframework.security.core.authority.SimpleGrantedAuthority",
            //      "authority" : "ROLE_ADM"
            //    } ] ],
            objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);

            objectMapper.activateDefaultTyping(
                LaissezFaireSubTypeValidator.instance,
                ObjectMapper.DefaultTyping.NON_FINAL,
                JsonTypeInfo.As.PROPERTY
            );
            return objectMapper;
        }

        @Bean
        public RedisSessionRepository redisSessionRepository(final RedisTemplate<String, Object> sessionRedisTemplate) {
            return new RedisSessionRepository(sessionRedisTemplate);
        }

        /**
         * Similar goal as UUID Type 7, but with security and usability enhancements.
         * Timestamp bytes is bucketed as 1 hour intervals, to prevent an adversary from guessing precise timing.
         * Randomness is increased to 32-bytes, the minimum for NIST to consider it sufficiently unique.
         * Append an unsigned short counter, to assist debugging within an instance of an application (e.g. 0001, ..., FFFE, FFFF, 0000, ...).
         * Base64-URL encoded, for use as a web session id cookie value, URL magic link query parameter, JWT jti/nonce, etc.
         * Data structure is...
         * Bytes (42):  timestamp bucket (8-bytes), random (32-bytes), rollover counter (2-bytes)
         * String (56): 42 bytes * 4 / 3 => 56 base64-url characters
         */
        public static class CustomSessionIdGenerator implements SessionIdGenerator {
            private static final long TIMESTAMP_GRANULARITY = 3600L; // 1 hour granularity
            private static final SecureRandom SECURE_RANDOM = new SecureRandom();
            private static final AtomicInteger COUNTER = new AtomicInteger(1);
            private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
            public @NotNull String generate() {
                return ENCODER.encodeToString(generateBytes());
            }
            public @NotNull byte[] generateBytes() {
                final long timestampBucket = Instant.now().getEpochSecond() / TIMESTAMP_GRANULARITY;
                final int  rolloverCounter = COUNTER.getAndIncrement();

                final byte[] timestamp = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(timestampBucket).array();
                final byte[] bytes = new byte[32]; // NIST minimum randomness to be considered unique
                SECURE_RANDOM.nextBytes(bytes);
                final byte[] counter = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(rolloverCounter).array();

                final byte[] id = new byte[42];
                System.arraycopy(timestamp, 0, id,  0, 8);
                System.arraycopy(bytes,     0, id,  8, 32);
                System.arraycopy(counter  , 2, id, 40, 2); // last 2-bytes of big endian int
                return id;
            }
        }
    }
    public static ObjectMapper newObjectMapper() {
        return new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
            .configure(SerializationFeature.INDENT_OUTPUT, true)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
            .configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, true)
            .configure(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY, true)
            .configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, false)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true)
            .configure(DeserializationFeature.FAIL_ON_UNEXPECTED_VIEW_PROPERTIES, true)
            .configure(DeserializationFeature.ACCEPT_FLOAT_AS_INT, false)
            ;
    }

    public PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions() {
        return PublicKeyCredentialCreationOptions.builder()
            .rp(PublicKeyCredentialRpEntity.builder().id("example.com").name("Example RP").build())
            .user(ImmutablePublicKeyCredentialUserEntity.builder().name("name").id(Bytes.random()).displayName("displayName").build())
            .challenge(Bytes.random())
            .pubKeyCredParams(List.of(PublicKeyCredentialParameters.ES384, PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.RS512))
            .timeout(Duration.ofSeconds(60))
            .excludeCredentials(Collections.singletonList(
                PublicKeyCredentialDescriptor.builder()
                .id(Bytes.random())
                .type(PublicKeyCredentialType.PUBLIC_KEY)
                .transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
                .build()
            ))
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                .userVerification(UserVerificationRequirement.PREFERRED)
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
                .build()
            )
            .attestation(AttestationConveyancePreference.DIRECT)
            .extensions(
                new ImmutableAuthenticationExtensionsClientInputs(new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true)))
            )
            .build();
    }

    public PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions() {
        return PublicKeyCredentialRequestOptions.builder()
            .challenge(Bytes.random())
            .timeout(Duration.ofSeconds(60))
            .rpId("example.com")
            .allowCredentials(
                List.of(
                    PublicKeyCredentialDescriptor.builder()
                        .id(Bytes.random())
                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                        .transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
                        .build()
                )
            )
            .userVerification(UserVerificationRequirement.PREFERRED)
            .extensions(
                new ImmutableAuthenticationExtensionsClientInputs(
                new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true))
            )
        )
        .build();
    }
}
