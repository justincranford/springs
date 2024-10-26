package com.github.justincranford.springs.persistenceorm.users.person;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converter;
import jakarta.persistence.Embeddable;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Embeddable
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SuppressWarnings("nls")
public class EmailAddressRfc5321 {
	@EmailRfc5321 // N.B. applied before converter
	@Convert(converter=LowercaseStringConverter.class) // N.B. applied after validator
    @Column(length=254,nullable=false) // RFCs 5321 & 5322
    @Size(min=3,max=254) // EX: 64 local @ 189 domain, 1 local @ 252 domain
    @NotNull
	@NotBlank
    private String emailAddress;

    @Documented
    @Constraint(validatedBy = EmailRfc5321Validator.class)
    @Target({ElementType.METHOD, ElementType.FIELD})
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface EmailRfc5321 {
        String message() default "Email address must conform to RFC 5321 format (e.g. max 252 chars), plus local part must be lowercase";
        Class<?>[] groups() default {};
        Class<? extends Payload>[] payload() default {};
    }

    public static class EmailRfc5321Validator implements ConstraintValidator<EmailRfc5321, String> {
        private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
        @Override
        public boolean isValid(final String email, final ConstraintValidatorContext context) {
        	return (email == null) || ((email.length() <= 254) && (EMAIL_PATTERN.matcher(email).matches()));
        }
    }

    @Converter
    public static class LowercaseStringConverter implements AttributeConverter<String, String> {
        @Override
        public String convertToDatabaseColumn(final String attribute) {
            return attribute == null ? null : attribute.toLowerCase();
        }
        @Override
        public String convertToEntityAttribute(final String dbData) {
            return dbData;
        }
    }
}
