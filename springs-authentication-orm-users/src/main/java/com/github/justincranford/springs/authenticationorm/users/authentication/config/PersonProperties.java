package com.github.justincranford.springs.authenticationorm.users.authentication.config;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import com.github.justincranford.springs.persistenceorm.users.person.enums.EmailAddressType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguage;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegion;
import com.github.justincranford.springs.persistenceorm.users.person.enums.LocationAddressType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonaType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PhoneNumberType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.Salutation;
import com.github.justincranford.springs.persistenceorm.users.person.enums.Status;
import com.github.justincranford.springs.persistenceorm.users.person.enums.Suffix;
import com.github.justincranford.springs.persistenceorm.users.person.enums.URLType;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Component
@ConfigurationProperties(prefix="springs.authenticationorm",ignoreUnknownFields=false,ignoreInvalidFields=false)
@PropertySource("classpath:springs-authentication-orm-users.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class PersonProperties {
    @NotNull
	@NotEmpty
    private Map<String, Person> users;
    public Map<String, Person> getUsers() {
        return this.users;
    }
    public void setUsers(Map<String, Person> users0) {
        this.users = users0;
    }

    @Getter
    @Setter
    public static class Person {
        private String username;
        private String password;
        private Name name;
        private LocalDate dateOfBirth;
        private Status status;
        private List<Language> languages;
        private List<String> timezones;
        private List<Persona> personas;

        @Getter
        @Setter
        public static class Language {
            private I18nLanguage i18n;
            private L10nRegion l10n;
            private boolean canSpeak;
            private boolean canListen;
            private boolean canRead;
            private boolean canWrite;
        }

        @Getter
        @Setter
        public static class Name {
            private Salutation salutation;
            private String first;
            private String middle;
            private String last;
            private Suffix suffix;
        }

        @Getter
        @Setter
        public static class Persona {
            private List<EmailAddress> emailAddresses;
            private List<PhoneNumber> phoneNumbers;
            private List<LocationAddress> locationAddresses;
            private List<URL> urls;
            private PersonaType personaType;
        }

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
