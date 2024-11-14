package com.github.justincranford.springs.persistenceorm.users.persona.email;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.util.Strings;

import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EmailRfc5321Validator implements ConstraintValidator<EmailRfc5321Constraints, String> {
//    private static final String EMAIL_REGEX = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
//    private static final String EMAIL_REGEX = "^(?!\\.)[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@([A-Za-z0-9-]+\\.)+[A-Za-z]{2,}$";
//    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    private int          emailMinLength                       = 3;
    private int          emailMaxLength                       = 254;

    private int          localPartMinLength                   = 1;
    private int          localPartMaxLength                   = 64;
    private String       localPartAllowedChars                = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+/=?^_{|}~\"-`.";
    private Set<Integer> localPartAllowedCharsSet             = this.localPartAllowedChars.codePoints().boxed().collect(Collectors.toSet());
	private String       localPartDisallowedSubstringStart    = ".";
	private String       localPartDisallowedSubstringAnywhere = "..";
	private String       localPartDisallowedSubstringEnd      = ".";

	private int          domainPartMinLength                  = 1;
    private int          domainPartMaxLength                  = 253;
    private int          domainLabelMinLength                 = 1;
    private int          domainLabelMaxLength                 = 63;
	private String       domainLabelAllowedChars              = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
    private Set<Integer> domainLabelAllowedCharsSet           = this.domainLabelAllowedChars.codePoints().boxed().collect(Collectors.toSet());
	private String       domainLabelDisallowedSubstringStart  = "-";
	private String       domainLabelDisallowedSubstringEnd    = "-";

 
    public static EmailRfc5321Validator create(final EmailRfc5321Constraints emailRfc5321Constraints) {
		final EmailRfc5321Validator emailRfc5321Validator = new EmailRfc5321Validator();
		emailRfc5321Validator.initialize(emailRfc5321Constraints);
		return emailRfc5321Validator;
	}

//    @Override
//    public void initialize(final EmailRfc5321Constraints emailRfc5321Constraints) {
//    	// do nothing, maybe allow some overrides in future (e.g. require lowercase local part, UNICODE code points beyond lower ASCII)
//    }

    @Override
    public boolean isValid(final String email, final ConstraintValidatorContext context) {
        return isValid(email, true); // throwException=false
    }

	public boolean isValid(final String email, final boolean throwException) {
		if (email == null) {
			return throwOrFalse(throwException, "Email must not be null");
        } else if (Strings.isBlank(email)) {
			return throwOrFalse(throwException, "Email must not be blank");
        } else if (email.length() < this.emailMinLength) {
			return throwOrFalse(throwException, "Email violates emailMinLength constraint: " + this.emailMinLength);
        } else if (email.length() > this.emailMaxLength) {
			return throwOrFalse(throwException, "Email violates emailMaxLength constraint: " + this.emailMaxLength);
        }

		final List<String> parts = StringUtil.split(email, "@"); // tokenize without regex overhead
		if (parts.size() != 2) {
			return throwOrFalse(throwException, "Email violates <username>@<domainPartname> format");
		}
		final String localPart = parts.removeFirst();
		final String domainPart = parts.removeLast();

		if (Strings.isBlank(localPart)) {
			return throwOrFalse(throwException, "Local part must not be blank");
        } else if (localPart.length() < this.localPartMinLength) {
			return throwOrFalse(throwException, "Local part violates localPartMinLength constraint: " + this.localPartMinLength);
        } else if (localPart.length() > this.localPartMaxLength) {
			return throwOrFalse(throwException, "Local part violates localPartMaxLength constraint: " + this.localPartMaxLength);
        } else if (localPart.codePoints().boxed().anyMatch(i -> !this.localPartAllowedCharsSet.contains(i))) {
			return throwOrFalse(throwException, "Local part violates localPartAllowedChars constraint: " + this.localPartAllowedChars);
        } else if (localPart.startsWith(this.localPartDisallowedSubstringStart)) {
			return throwOrFalse(throwException, "Local part violates localPartDisallowedSubstringStart constraint: " + this.localPartDisallowedSubstringStart);
        } else if (localPart.contains(this.localPartDisallowedSubstringAnywhere)) {
			return throwOrFalse(throwException, "Local part violates localPartDisallowedSubstringAnywhere constraint: " + this.localPartDisallowedSubstringAnywhere);
        } else if (localPart.endsWith(this.localPartDisallowedSubstringEnd)) {
			return throwOrFalse(throwException, "Local part violates localPartDisallowedSubstringEnd constraint: " + this.localPartDisallowedSubstringEnd);
        }

        if (Strings.isBlank(domainPart)) {
			return throwOrFalse(throwException, "Domain part must not be blank");
        } else if (domainPart.length() < this.domainPartMinLength) {
			return throwOrFalse(throwException, "Domain part violates domainPartMinLength constraint: " + this.domainPartMinLength);
        } else if (domainPart.length() > this.domainPartMaxLength) {
			return throwOrFalse(throwException, "Domain part violates domainPartMaxLength constraint: " + this.domainPartMaxLength);
        }

        final List<String> domainLabels = StringUtil.split(domainPart, "."); // tokenize without regex overhead
		for (final String domainLabel : domainLabels) {
			if (domainLabel.length() < this.domainLabelMinLength) {
				return throwOrFalse(throwException, "Domain label violates domainLabelMinLength constraint: " + this.domainLabelMinLength);
			} else if (domainLabel.length() > this.domainLabelMaxLength) {
				return throwOrFalse(throwException, "Domain label violates domainPartMaxLength constraint: " + this.domainLabelMaxLength);
	        } else if (domainLabel.codePoints().boxed().anyMatch(i -> !this.domainLabelAllowedCharsSet.contains(i))) {
				return throwOrFalse(throwException, "Domain part violates domainLabelAllowedChars constraint: " + this.domainLabelAllowedChars);
			} else if (domainLabel.startsWith(this.domainLabelDisallowedSubstringStart)) {
				return throwOrFalse(throwException, "Domain label violates domainLabelDisallowedSubstringStart constraint: " + this.domainLabelDisallowedSubstringStart);
			} else if (domainLabel.endsWith(this.domainLabelDisallowedSubstringEnd)) {
				return throwOrFalse(throwException, "Domain label violates domainLabelDisallowedSubstringEnd constraint: " + this.domainLabelDisallowedSubstringEnd);
			}
		}

//        if (!(EMAIL_PATTERN.matcher(email).matches())) {
//			return throwOrFalse(throwException, "Email does not match regex");
//    	}
		return true;
    }

	private static boolean throwOrFalse(final boolean throwException, final String msg) {
		log.error(msg);
		if (throwException) {
			throw new RuntimeException(msg);
		}
		return false;
	}
}
