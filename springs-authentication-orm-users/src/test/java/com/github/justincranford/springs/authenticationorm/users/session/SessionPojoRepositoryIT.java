package com.github.justincranford.springs.authenticationorm.users.session;

import static com.github.justincranford.springs.util.basic.SecureRandomUtil.SECURE_RANDOM;
import static com.github.justincranford.springs.util.basic.SecureRandomUtil.randomEmailAddress;
import static com.github.justincranford.springs.util.basic.SecureRandomUtil.randomEnumElement;
import static com.github.justincranford.springs.util.basic.SecureRandomUtil.randomString;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.springs.authenticationorm.users.AbstractIT;
import com.github.justincranford.springs.persistenceorm.users.person.LanguageOrm;
import com.github.justincranford.springs.persistenceorm.users.person.NameOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguageType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegionType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.persistenceorm.users.persona.EmailAddressOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.EmailAddressRfc5321Orm;
import com.github.justincranford.springs.persistenceorm.users.persona.LocationAddressOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm.PersonaOrmBuilder;
import com.github.justincranford.springs.persistenceorm.users.persona.PhoneNumberOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.UrlOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.EmailAddressType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.LocationAddressType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PhoneNumberType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.URLType;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Transactional
@Slf4j
@SuppressWarnings({"nls", "unused", "rawtypes"})
public class SessionPojoRepositoryIT extends AbstractIT {
	private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";
	private static final String INDEX_NAME = FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;
	private SecurityContext context;
	private SecurityContext changedContext;
	private PersonaOrm personaOrm;
	private PersonOrm personOrm;

	@BeforeEach
	void setUp() {
		this.context = SecurityContextHolder.createEmptyContext();
		this.context.setAuthentication(new UsernamePasswordAuthenticationToken("username-" + UUID.randomUUID(), "na", AuthorityUtils.createAuthorityList("ROLE_USER")));
		this.changedContext = SecurityContextHolder.createEmptyContext();
		this.changedContext.setAuthentication(new UsernamePasswordAuthenticationToken("changedContext-" + UUID.randomUUID(), "na", AuthorityUtils.createAuthorityList("ROLE_USER")));

		this.personOrm = generatePerson();
		super.personOrmRepository().save(this.personOrm);

		if (SECURE_RANDOM.nextBoolean()) {
			this.personaOrm = generatePersona(this.personOrm);
			super.personaOrmRepository().save(this.personaOrm);
		}
	}

	public static PersonOrm generatePerson() {
		return PersonOrm.builder()
			.username("username-" + randomString(Base64Util.URL, 32))
			.password(PasswordOrm.builder().password("password" + randomString(Base64Util.URL, 32)).build())
			.name(NameOrm.builder()
				.first("First "   + randomString(Base64Util.URL, 32))
				.middle("Middle " + randomString(Base64Util.URL, 32))
				.last("Last "     + randomString(Base64Util.URL, 32))
				.build())
			.dateOfBirth(LocalDate.ofYearDay(SECURE_RANDOM.nextInt(100) + 1923, SECURE_RANDOM.nextInt(365) + 1))
			.status(SecureRandomUtil.randomEnumElement(PersonStatusType.class))
			.languages(List.of(LanguageOrm.builder().i18n(SecureRandomUtil.randomEnumElement(I18nLanguageType.class)).l10n(SecureRandomUtil.randomEnumElement(L10nRegionType.class)).build()))
			.timezones(List.of(TimeZone.getTimeZone("Americas/Toronto").toString()))
			.build();
	}

	public static PersonaOrm generatePersona(@NotNull final PersonOrm personOrm) {
		final PersonaOrmBuilder personaBuilder = PersonaOrm.builder();
		if (SECURE_RANDOM.nextBoolean()) {
			final int rank = SECURE_RANDOM.nextInt(5);
			final List<EmailAddressOrm> emailAddresses = new ArrayList<>(rank);
			for (int emailAddressIndex : IntStream.rangeClosed(1, rank).boxed().toList()) {
				emailAddresses.add(
					EmailAddressOrm.builder()
						.rank(emailAddressIndex)
						.emailAddress(EmailAddressRfc5321Orm.builder().emailAddress(randomEmailAddress()).build())
						.type(SecureRandomUtil.randomEnumElement(EmailAddressType.class))
						.build()
				);
			}
			personaBuilder.emailAddresses(emailAddresses);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			final int numPhoneNumbers = SECURE_RANDOM.nextInt(5);
			final List<PhoneNumberOrm> phoneNumbers = new ArrayList<>(numPhoneNumbers);
			for (int rank : IntStream.rangeClosed(1, numPhoneNumbers).boxed().toList()) {
				phoneNumbers.add(
					PhoneNumberOrm.builder()
						.rank(rank)
						.phoneNumber("+1" + SECURE_RANDOM.nextLong(1_000_000_000L, 9_999_999_999L))
						.talk(SECURE_RANDOM.nextBoolean())
						.text(SECURE_RANDOM.nextBoolean())
						.data(SECURE_RANDOM.nextBoolean())
						.type(randomEnumElement(PhoneNumberType.class))
						.build()
					);
			}
			personaBuilder.phoneNumbers(phoneNumbers);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			final int numLocationAddresses = SECURE_RANDOM.nextInt(5);
			final List<LocationAddressOrm> locationAddresses = new ArrayList<>(numLocationAddresses);
			for (int rank : IntStream.rangeClosed(1, numLocationAddresses).boxed().toList()) {
				locationAddresses.add(
					LocationAddressOrm.builder()
						.rank(rank)
						.street1(SECURE_RANDOM.nextInt() + " Street Ave")
						.street2(SECURE_RANDOM.nextBoolean() ? null : "Apartment " + SECURE_RANDOM.nextInt())
						.city("Ottawa")
						.state("Ontario")
						.country("Canada")
						.type(SecureRandomUtil.randomEnumElement(LocationAddressType.class))
						.build()
				);
			}
			personaBuilder.locationAddresses(locationAddresses);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			final int numUrls = SECURE_RANDOM.nextInt(5);
			final List<UrlOrm> urls = new ArrayList<>(numUrls);
			for (int rank : IntStream.rangeClosed(1, numUrls).boxed().toList()) {
				urls.add(
					UrlOrm.builder()
						.rank(rank)
						.url("https://example.com")
						.type(randomEnumElement(URLType.class))
						.build()
				);
			}
			personaBuilder.urls(urls);
		}
		if (SECURE_RANDOM.nextBoolean()) {
			personaBuilder.personaType(randomEnumElement(PersonaType.class));
		}
		personaBuilder.person(personOrm);

		final PersonaOrm personaOrm = personaBuilder.build();
		personOrm.personas().add(personaOrm);
		return personaOrm;
	}

	private SessionPojo createSession() {
		final SessionPojo sessionPojo = super.repository().createSession();
		sessionPojo.setPerson(this.personOrm);
		sessionPojo.setPersona(this.personaOrm);
		return sessionPojo;
	}

	@Test
	void saveWhenNoAttributesThenCanBeFound1() {
		final SessionPojo toSave = createSession();
		super.repository().save(toSave);
		final SessionPojo found = super.repository().findById(toSave.getId());
		assertThat(found).isNotNull();

		super.repository().deleteById(toSave.getId());

		final SessionPojo notFound = super.repository().findById(toSave.getId());
		assertThat(notFound).isNull();
	}

	@Test
	void saves1() {
		String username = "saves-" + System.currentTimeMillis();
		String expectedAttributeName = "a";
		String expectedAttributeValue = "b";

		SessionPojo toSave = createSession();
		toSave.setAttribute(expectedAttributeName, expectedAttributeValue);
		Authentication toSaveToken = new UsernamePasswordAuthenticationToken(username, "password", AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContext toSaveContext = SecurityContextHolder.createEmptyContext();
		toSaveContext.setAuthentication(toSaveToken);
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, toSaveContext);
		toSave.setAttribute(INDEX_NAME, username);

		super.repository().save(toSave);

		final List<SessionPojo> all2a = super.repository().findAll();
		log.info("all2a: {}", all2a);

		SessionPojo session = super.repository().findById(toSave.getId());

		assertThat(session.getId()).isEqualTo(toSave.getId());
		assertThat(session.getAttributeNames()).isEqualTo(toSave.getAttributeNames());
		assertThat(session.<String>getAttribute(expectedAttributeName))
			.isEqualTo(toSave.getAttribute(expectedAttributeName));

		super.repository().deleteById(toSave.getId());

		final List<SessionPojo> all2b = super.repository().findAll();
		log.info("all2b: {}", all2b);

		assertThat(super.repository().findById(toSave.getId())).isNull();
	}

	@Test
	void saveWhenNoAttributesThenCanBeFound() {
		SessionPojo toSave = createSession();

		super.repository().save(toSave);
		SessionPojo session = super.repository().findById(toSave.getId());

		assertThat(session).isNotNull();
	}

	@Test
	void saves() {
		String username = "saves-" + System.currentTimeMillis();

		SessionPojo toSave = createSession();
		String expectedAttributeName = "a";
		String expectedAttributeValue = "b";
		toSave.setAttribute(expectedAttributeName, expectedAttributeValue);
		Authentication toSaveToken = new UsernamePasswordAuthenticationToken(username, "password",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContext toSaveContext = SecurityContextHolder.createEmptyContext();
		toSaveContext.setAuthentication(toSaveToken);
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, toSaveContext);
		toSave.setAttribute(INDEX_NAME, username);

		super.repository().save(toSave);

		SessionPojo session = super.repository().findById(toSave.getId());

		assertThat(session.getId()).isEqualTo(toSave.getId());
		assertThat(session.getAttributeNames()).isEqualTo(toSave.getAttributeNames());
		assertThat(session.<String>getAttribute(expectedAttributeName))
			.isEqualTo(toSave.getAttribute(expectedAttributeName));

		super.repository().deleteById(toSave.getId());

		assertThat(super.repository().findById(toSave.getId())).isNull();
	}

	@Test
	@Transactional(readOnly = true)
	void savesInReadOnlyTransaction() {
		SessionPojo toSave = createSession();

		super.repository().save(toSave);
	}

	@Test
	void putAllOnSingleAttrDoesNotRemoveOld() {
		SessionPojo toSave = createSession();
		toSave.setAttribute("a", "b");

		super.repository().save(toSave);
		toSave = super.repository().findById(toSave.getId());

		toSave.setAttribute("1", "2");

		super.repository().save(toSave);
		toSave = super.repository().findById(toSave.getId());

		SessionPojo session = super.repository().findById(toSave.getId());
		assertThat(session.getAttributeNames().size()).isEqualTo(2);
		assertThat(session.<String>getAttribute("a")).isEqualTo("b");
		assertThat(session.<String>getAttribute("1")).isEqualTo("2");

		super.repository().deleteById(toSave.getId());
	}

	@Test
	void updateLastAccessedTime() {
		SessionPojo toSave = createSession();
		toSave.setLastAccessedTime(Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1));

		super.repository().save(toSave);

		Instant lastAccessedTime = Instant.now();
		toSave.setLastAccessedTime(lastAccessedTime);
		super.repository().save(toSave);

		SessionPojo session = super.repository().findById(toSave.getId());

		assertThat(session).isNotNull();
		assertThat(session.isExpired()).isFalse();
		assertThat(session.getLastAccessedTime().truncatedTo(ChronoUnit.MILLIS))
			.isEqualTo(lastAccessedTime.truncatedTo(ChronoUnit.MILLIS));
	}

	@Test
	void findByPrincipalName() {
		String principalName = "findByPrincipalName" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());

		super.repository().deleteById(toSave.getId());

		findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME, principalName);

		assertThat(findByPrincipalName).hasSize(0);
		assertThat(findByPrincipalName.keySet()).doesNotContain(toSave.getId());
	}

	@Test
	void findByPrincipalNameExpireRemovesIndex() {
		String principalName = "findByPrincipalNameExpireRemovesIndex" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);
		toSave.setLastAccessedTime(Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1));

		super.repository().save(toSave);
		super.repository().cleanUpExpiredSessions();

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);

		assertThat(findByPrincipalName).hasSize(0);
		assertThat(findByPrincipalName.keySet()).doesNotContain(toSave.getId());
	}

	@Test
	void findByPrincipalNameNoPrincipalNameChange() {
		String principalName = "findByPrincipalNameNoPrincipalNameChange" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		toSave.setAttribute("other", "value");
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findByPrincipalNameNoPrincipalNameChangeReload() {
		String principalName = "findByPrincipalNameNoPrincipalNameChangeReload" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		toSave = super.repository().findById(toSave.getId());

		toSave.setAttribute("other", "value");
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findByDeletedPrincipalName() {
		String principalName = "findByDeletedPrincipalName" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		toSave.setAttribute(INDEX_NAME, null);
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);

		assertThat(findByPrincipalName).isEmpty();
	}

	@Test
	void findByChangedPrincipalName() {
		String principalName = "findByChangedPrincipalName" + UUID.randomUUID();
		String principalNameChanged = "findByChangedPrincipalName" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		toSave.setAttribute(INDEX_NAME, principalNameChanged);
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);
		assertThat(findByPrincipalName).isEmpty();

		findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME, principalNameChanged);

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findByDeletedPrincipalNameReload() {
		String principalName = "findByDeletedPrincipalName" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		SessionPojo getSession = super.repository().findById(toSave.getId());
		getSession.setAttribute(INDEX_NAME, null);
		super.repository().save(getSession);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);

		assertThat(findByPrincipalName).isEmpty();
	}

	@Test
	void findByChangedPrincipalNameReload() {
		String principalName = "findByChangedPrincipalName" + UUID.randomUUID();
		String principalNameChanged = "findByChangedPrincipalName" + UUID.randomUUID();
		SessionPojo toSave = createSession();
		toSave.setAttribute(INDEX_NAME, principalName);

		super.repository().save(toSave);

		SessionPojo getSession = super.repository().findById(toSave.getId());

		getSession.setAttribute(INDEX_NAME, principalNameChanged);
		super.repository().save(getSession);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				principalName);
		assertThat(findByPrincipalName).isEmpty();

		findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME, principalNameChanged);

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findBySecurityPrincipalName() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());

		super.repository().deleteById(toSave.getId());

		findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME, getSecurityName());

		assertThat(findByPrincipalName).hasSize(0);
		assertThat(findByPrincipalName.keySet()).doesNotContain(toSave.getId());
	}

	@Test
	void findBySecurityPrincipalNameExpireRemovesIndex() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);
		toSave.setLastAccessedTime(Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1));

		super.repository().save(toSave);
		super.repository().cleanUpExpiredSessions();

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());

		assertThat(findByPrincipalName).hasSize(0);
		assertThat(findByPrincipalName.keySet()).doesNotContain(toSave.getId());
	}

	@Test
	void findByPrincipalNameNoSecurityPrincipalNameChange() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		toSave.setAttribute("other", "value");
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findByPrincipalNameNoSecurityPrincipalNameChangeReload() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		toSave = super.repository().findById(toSave.getId());

		toSave.setAttribute("other", "value");
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findByDeletedSecurityPrincipalName() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		toSave.setAttribute(SPRING_SECURITY_CONTEXT, null);
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());

		assertThat(findByPrincipalName).isEmpty();
	}

	@Test
	void findByChangedSecurityPrincipalName() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.changedContext);
		super.repository().save(toSave);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());
		assertThat(findByPrincipalName).isEmpty();

		findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME, getChangedSecurityName());

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void findByDeletedSecurityPrincipalNameReload() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		SessionPojo getSession = super.repository().findById(toSave.getId());
		getSession.setAttribute(INDEX_NAME, null);
		super.repository().save(getSession);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getChangedSecurityName());

		assertThat(findByPrincipalName).isEmpty();
	}

	@Test
	void findByChangedSecurityPrincipalNameReload() {
		SessionPojo toSave = createSession();
		toSave.setAttribute(SPRING_SECURITY_CONTEXT, this.context);

		super.repository().save(toSave);

		SessionPojo getSession = super.repository().findById(toSave.getId());

		getSession.setAttribute(SPRING_SECURITY_CONTEXT, this.changedContext);
		super.repository().save(getSession);

		Map<String, SessionPojo> findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME,
				getSecurityName());
		assertThat(findByPrincipalName).isEmpty();

		findByPrincipalName = super.repository().findByIndexNameAndIndexValue(INDEX_NAME, getChangedSecurityName());

		assertThat(findByPrincipalName).hasSize(1);
		assertThat(findByPrincipalName.keySet()).containsOnly(toSave.getId());
	}

	@Test
	void cleanupInactiveSessionsUsingRepositoryDefinedInterval() {
		SessionPojo session = createSession();

		super.repository().save(session);

		assertThat(super.repository().findById(session.getId())).isNotNull();

		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNotNull();

		Instant now = Instant.now();

		session.setLastAccessedTime(now.minus(10, ChronoUnit.MINUTES));
		super.repository().save(session);
		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNotNull();

		session.setLastAccessedTime(now.minus(30, ChronoUnit.MINUTES));
		super.repository().save(session);
		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNull();
	}

	// gh-580
	@Test
	void cleanupInactiveSessionsUsingSessionDefinedInterval() {
		SessionPojo session = createSession();
		session.setMaxInactiveInterval(Duration.ofMinutes(45));

		super.repository().save(session);

		assertThat(super.repository().findById(session.getId())).isNotNull();

		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNotNull();

		Instant now = Instant.now();

		session.setLastAccessedTime(now.minus(40, ChronoUnit.MINUTES));
		super.repository().save(session);
		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNotNull();

		session.setLastAccessedTime(now.minus(50, ChronoUnit.MINUTES));
		super.repository().save(session);
		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNull();
	}

	@Test
	void cleanupExpiredSessionsWhenMaxInactiveIntervalNegativeThenSessionNotDeleted() {
		SessionPojo session = createSession();
		session.setMaxInactiveInterval(Duration.ofSeconds(-1));
		session.setLastAccessedTime(Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1));

		super.repository().save(session);
		super.repository().cleanUpExpiredSessions();

		assertThat(super.repository().findById(session.getId())).isNotNull();
	}

	@Test
	void changeSessionIdWhenOnlyChangeId() {
		String attrName = "changeSessionId";
		String attrValue = "changeSessionId-value";
		SessionPojo toSave = createSession();
		toSave.setAttribute(attrName, attrValue);

		super.repository().save(toSave);

		SessionPojo findById = super.repository().findById(toSave.getId());

		assertThat(findById.<String>getAttribute(attrName)).isEqualTo(attrValue);

		String originalFindById = findById.getId();
		String changeSessionId = findById.changeSessionId();

		super.repository().save(findById);

		assertThat(super.repository().findById(originalFindById)).isNull();

		SessionPojo findByChangeSessionId = super.repository().findById(changeSessionId);

		assertThat(findByChangeSessionId.<String>getAttribute(attrName)).isEqualTo(attrValue);
	}

	@Test
	void changeSessionIdWhenChangeTwice() {
		SessionPojo toSave = createSession();

		super.repository().save(toSave);

		String originalId = toSave.getId();
		String changeId1 = toSave.changeSessionId();
		String changeId2 = toSave.changeSessionId();

		super.repository().save(toSave);

		assertThat(super.repository().findById(originalId)).isNull();
		assertThat(super.repository().findById(changeId1)).isNull();
		assertThat(super.repository().findById(changeId2)).isNotNull();
	}

	@Test
	void changeSessionIdWhenSetAttributeOnChangedSession() {
		String attrName = "changeSessionId";
		String attrValue = "changeSessionId-value";

		SessionPojo toSave = createSession();

		super.repository().save(toSave);

		SessionPojo findById = super.repository().findById(toSave.getId());

		findById.setAttribute(attrName, attrValue);

		String originalFindById = findById.getId();
		String changeSessionId = findById.changeSessionId();

		super.repository().save(findById);

		assertThat(super.repository().findById(originalFindById)).isNull();

		SessionPojo findByChangeSessionId = super.repository().findById(changeSessionId);

		assertThat(findByChangeSessionId.<String>getAttribute(attrName)).isEqualTo(attrValue);
	}

	@Test
	void changeSessionIdWhenHasNotSaved() {
		SessionPojo toSave = createSession();
		String originalId = toSave.getId();
		toSave.changeSessionId();

		super.repository().save(toSave);

		assertThat(super.repository().findById(toSave.getId())).isNotNull();
		assertThat(super.repository().findById(originalId)).isNull();
	}

	@Test // gh-1070
	void saveUpdatedAddAndModifyAttribute() {
		SessionPojo session = createSession();
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		session.setAttribute("testName", "testValue1");
		session.setAttribute("testName", "testValue2");
		super.repository().save(session);
		session = super.repository().findById(session.getId());

		assertThat(session.<String>getAttribute("testName")).isEqualTo("testValue2");
	}

	@Test // gh-1070
	void saveUpdatedAddAndRemoveAttribute() {
		SessionPojo session = createSession();
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		session.setAttribute("testName", "testValue");
		session.removeAttribute("testName");
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		final Object attribute = session.<String>getAttribute("testName");
		assertThat(attribute).isNull();
	}

	@Test // gh-1070
	void saveUpdatedModifyAndRemoveAttribute() {
		SessionPojo session = createSession();
		session.setAttribute("testName", "testValue1");
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		session.setAttribute("testName", "testValue2");
		session.removeAttribute("testName");
		super.repository().save(session);
		session = super.repository().findById(session.getId());

		assertThat(session.<String>getAttribute("testName")).isNull();
	}

	@Test // gh-1070
	void saveUpdatedRemoveAndAddAttribute() {
		SessionPojo session = createSession();
		session.setAttribute("testName", "testValue1");
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		session.removeAttribute("testName");
		session.setAttribute("testName", "testValue2");
		super.repository().save(session);
		session = super.repository().findById(session.getId());

		assertThat(session.<String>getAttribute("testName")).isEqualTo("testValue2");
	}

	@Test // gh-1031
	void saveDeleted() {
		SessionPojo session = createSession();
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		super.repository().deleteById(session.getId());
		session.setLastAccessedTime(Instant.now());
		super.repository().save(session);

		assertThat(super.repository().findById(session.getId())).isNull();
	}

	@Test // gh-1031
	void saveDeletedAddAttribute() {
		SessionPojo session = createSession();
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		super.repository().deleteById(session.getId());
		session.setLastAccessedTime(Instant.now());
		session.setAttribute("testName", "testValue1");
		super.repository().save(session);

		assertThat(super.repository().findById(session.getId())).isNull();
	}

	@Disabled("Makes assumptions about implementation, instead of sticking to SessionRepository APIs")
	@Test // gh-1133
	void sessionFromStoreResolvesAttributesLazily() {
		SessionPojo session = createSession();
		session.setAttribute("attribute1", "value1");
		session.setAttribute("attribute2", "value2");
		super.repository().save(session);
		session = super.repository().findById(session.getId());
		MapSession delegate = (MapSession) ReflectionTestUtils.getField(session, "delegate");

		Supplier attribute1 = delegate.getAttribute("attribute1");
		assertThat(ReflectionTestUtils.getField(attribute1, "value")).isNull();
		assertThat((String) session.getAttribute("attribute1")).isEqualTo("value1");
		assertThat(ReflectionTestUtils.getField(attribute1, "value")).isEqualTo("value1");
		Supplier attribute2 = delegate.getAttribute("attribute2");
		assertThat(ReflectionTestUtils.getField(attribute2, "value")).isNull();
		assertThat((String) session.getAttribute("attribute2")).isEqualTo("value2");
		assertThat(ReflectionTestUtils.getField(attribute2, "value")).isEqualTo("value2");
	}

	@Disabled("Makes assumptions about implementation, instead of sticking to SessionRepository APIs")
	@Test // gh-1203
	void saveWithLargeAttribute() {
		String attributeName = "largeAttribute";
		int arraySize = 4000;

		SessionPojo session = createSession();
		session.setAttribute(attributeName, new byte[arraySize]);
		super.repository().save(session);
		session = super.repository().findById(session.getId());

		assertThat(session).isNotNull();
		assertThat((byte[]) session.getAttribute(attributeName)).hasSize(arraySize);
	}

	private String getSecurityName() {
		return this.context.getAuthentication().getName();
	}

	private String getChangedSecurityName() {
		return this.changedContext.getAuthentication().getName();
	}
}
