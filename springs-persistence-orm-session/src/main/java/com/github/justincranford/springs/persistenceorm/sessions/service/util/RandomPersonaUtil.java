package com.github.justincranford.springs.persistenceorm.sessions.service.util;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
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
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import jakarta.validation.constraints.NotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static com.github.justincranford.springs.util.basic.SecureRandomUtil.SECURE_RANDOM;
import static com.github.justincranford.springs.util.basic.SecureRandomUtil.randomEmailAddress;
import static com.github.justincranford.springs.util.basic.SecureRandomUtil.randomEnumElement;

public class RandomPersonaUtil {
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
}
