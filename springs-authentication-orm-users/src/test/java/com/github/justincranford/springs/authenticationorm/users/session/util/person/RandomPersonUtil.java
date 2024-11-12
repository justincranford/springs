package com.github.justincranford.springs.authenticationorm.users.session.util.person;

import static com.github.justincranford.springs.util.basic.SecureRandomUtil.SECURE_RANDOM;
import static com.github.justincranford.springs.util.basic.SecureRandomUtil.randomString;

import java.time.LocalDate;
import java.util.List;
import java.util.TimeZone;

import com.github.justincranford.springs.persistenceorm.users.person.LanguageOrm;
import com.github.justincranford.springs.persistenceorm.users.person.NameOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguageType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegionType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;

public class RandomPersonUtil {
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
}

