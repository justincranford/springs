package com.github.justincranford.springs.persistenceorm.users.properties;
import java.time.LocalDate;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguageType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegionType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.SalutationType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.SuffixType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.EmailAddressType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.LocationAddressType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PhoneNumberType;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.URLType;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Component
@ConfigurationProperties(prefix="springs.persistenceorm",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-persistence-orm-users.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmUsersProperties {
    @NotNull
    @NotEmpty
    private List<SpringsPersistenceOrmUsersProperties.Person> users;
    public List<SpringsPersistenceOrmUsersProperties.Person> getUsers() {
        return this.users;
    }
    public void setUsers(List<SpringsPersistenceOrmUsersProperties.Person> _users) {
        this.users = _users;
    }

    @Getter
    @Setter
    public static class Person {
        private String username;
        private String password;
        private Name name;
        private LocalDate dateOfBirth;
        private PersonStatusType status;
        private List<Language> languages;
        private List<String> timezones;
        private List<Persona> personas;

        @Getter
        @Setter
        public static class Language {
            private I18nLanguageType i18n;
            private L10nRegionType l10n;
            private boolean canSpeak;
            private boolean canListen;
            private boolean canRead;
            private boolean canWrite;
        }

        @Getter
        @Setter
        public static class Name {
            private SalutationType salutation;
            private String first;
            private String middle;
            private String last;
            private SuffixType suffix;
        }

        @Getter
        @Setter
        public static class Persona {
            private List<EmailAddress> emailAddresses;
            private List<PhoneNumber> phoneNumbers;
            private List<LocationAddress> locationAddresses;
            private List<URL> urls;
            private PersonaType personaType;

            @Getter
            @Setter
            public static class EmailAddress {
                private String emailAddress;
                private EmailAddressType type;
            }

            @Getter
            @Setter
            public static class PhoneNumber {
                private String phoneNumber;
                private boolean canTalk;
                private boolean canText;
                private boolean hasData;
                private PhoneNumberType type;
            }

            @Getter
            @Setter
            public static class LocationAddress {
                private String street1;
                private String street2;
                private String city;
                private String state;
                private String country;
                private LocationAddressType type;
            }

            @Getter
            @Setter
            public static class URL {
                private String url;
                private URLType type;
            }
        }
    }
}
