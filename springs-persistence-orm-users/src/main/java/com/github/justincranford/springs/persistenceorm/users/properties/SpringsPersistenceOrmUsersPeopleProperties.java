package com.github.justincranford.springs.persistenceorm.users.properties;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguageType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegionType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.SalutationType;
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
@ConfigurationProperties(prefix="springs.persistenceorm.users", ignoreUnknownFields=false)
@PropertySource("classpath:springs-persistence-orm-users.properties")
@Validated
@Getter
@Setter
@ToString
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsPersistenceOrmUsersPeopleProperties {
    @NotNull
    @NotEmpty
    @Builder.Default
    private List<SpringsPersistenceOrmUsersPeopleProperties.Person> people = new ArrayList<>();

    @Validated
    @Getter
    @Setter
    @ToString
    public static class Person {
    	@NotEmpty
        private String username;
    	@Nullable
        private String password;
    	@NotNull
        private Name name;
    	@NotNull
        private LocalDate dateOfBirth;
    	@NotNull
        private PersonStatusType status;
        @NotNull
        private List<Language> languages = new ArrayList<>();
        @NotNull
        private List<String> timezones = new ArrayList<>();
    	@NotEmpty
        private List<Persona> personas = new ArrayList<>();

        @Validated
        @Getter
        @Setter
        @ToString
        public static class Language {
        	@NotNull
            private I18nLanguageType i18n;
        	@NotNull
            private L10nRegionType l10n;
            private boolean canSpeak;
            private boolean canListen;
            private boolean canRead;
            private boolean canWrite;
        }

        @Validated
        @Getter
        @Setter
        @ToString
        public static class Name {
        	@Nullable
            private SalutationType salutation;
        	@NotEmpty
            private String first;
        	@Nullable
            private String middle;
        	@Nullable
            private String last;
        	@Nullable
            private SuffixType suffix;
        }

        @Validated
        @Getter
        @Setter
        @ToString
        public static class Persona {
        	@NotEmpty
            private List<EmailAddress> emailAddresses = new ArrayList<>();
        	@NotEmpty
            private List<PhoneNumber> phoneNumbers = new ArrayList<>();
            @NotNull
            private List<LocationAddress> locationAddresses = new ArrayList<>();
            @NotNull
            private List<URL> urls = new ArrayList<>();
            @NotNull
            private PersonaType personaType;

            @Validated
            @Getter
            @Setter
            @ToString
            public static class EmailAddress {
            	@NotEmpty
                private String emailAddress;
            	@NotNull
                private EmailAddressType type;
            }

            @Validated
            @Getter
            @Setter
            @ToString
            public static class PhoneNumber {
            	@NotEmpty
                private String phoneNumber;
                private boolean canTalk;
                private boolean canText;
                private boolean hasData;
            	@NotNull
                private PhoneNumberType type;
            }

            @Validated
            @Getter
            @Setter
            @ToString
            public static class LocationAddress {
            	@NotEmpty
                private String street1;
            	@Nullable
                private String street2;
            	@NotEmpty
                private String city;
            	@NotEmpty
                private String state;
            	@NotEmpty
                private String country;
            	@NotNull
                private LocationAddressType type;
            }

            @Validated
            @Getter
            @Setter
            @ToString
            public static class URL {
            	@NotEmpty
                private String url;
            	@Nullable
                private URLType type;
            }
        }
    }
}
