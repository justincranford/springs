package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class JwtClaimSetUtil {
    public static boolean validate(final JWTClaimsSet jwtClaimsSet) throws JOSEException, ParseException {
        return validate(jwtClaimsSet, null, null, null);
    }

    public static boolean validate(final JWTClaimsSet jwtClaimsSet, final String targetIss, final String targetAud, final String targetSub) throws JOSEException, ParseException {
        final String       iss   = jwtClaimsSet.getIssuer();
        final List<String> aud   = audList(jwtClaimsSet.getClaim("aud"));
        final String       sub   = jwtClaimsSet.getSubject();
        final String       jti   = jwtClaimsSet.getJWTID();
        final String       nonce = jwtClaimsSet.getStringClaim("nonce");
        final Date         iat   = jwtClaimsSet.getIssueTime();
        final Date         nbf   = jwtClaimsSet.getNotBeforeTime();
        final Date         exp   = jwtClaimsSet.getExpirationTime();
        final List<String> scope = scopeList(jwtClaimsSet.getStringClaim("scope"));

        notNullAndNotBlank                       ("iss",   iss);
        notNullNotEmptyAndNotNullNotBlankElements("aud",   aud);
        notNullAndNotBlank                       ("sub",   sub);
        notBlank                                 ("jti",   jti);
        notBlank                                 ("nonce", nonce);
        notNullNotEmptyAndNotNullNotBlankElements("scope", scope);
        equalOrAfter                             ("nbf",   nbf, "iat", iat);
        after                                    ("exp",   exp, "iat", iat);
        after                                    ("exp",   exp, "nbf", nbf);
        notNullEqualOrAfter                      ("iat",   iat, "now", new Date());
        after                                    ("exp",   exp, "now", new Date());
        match   ("iss", iss, targetIss);
        contains("aud", aud, targetAud);
        match   ("sub", sub, targetSub);
        return true;
    }

    private static void notNullNotEmptyAndNotNullNotBlankElements(final String claim, final Collection<String> values) throws JOSEException {
        if (values == null) {
            throw new JOSEException("Required claim '" + claim + "' cannot be null");
        } else if (values.isEmpty()) {
            throw new JOSEException("Required claim '" + claim + "' cannot be empty");
        } else if (values.stream().anyMatch(Objects::isNull)) {
            throw new JOSEException("Required claim '" + claim + "' cannot contain null values");
        } else if (values.stream().anyMatch(String::isBlank)) {
            throw new JOSEException("Required claim '" + claim + "' cannot contain blank values");
        }
    }

    private static void notNullAndNotBlank(final String claim, final String value) throws JOSEException {
        if (value == null) {
            throw new JOSEException("Required claim '" + claim + "' cannot be null");
        } else if (value.isBlank()) {
            throw new JOSEException("Required claim '" + claim + "' cannot be blank");
        }
    }

    private static void notNullEqualOrAfter(final String claim, final Date value, final String otherClaim, final Date otherValue) throws JOSEException {
        if (value == null) {
            throw new JOSEException("Required claim '" + claim + "' cannot be null");
        } else if (!value.before(otherValue)) {
            throw new JOSEException("Required claim '" + claim + "' " + value + " cannot be equal or after " + otherClaim + " " + otherValue);
        }
    }

    private static void equalOrAfter(final String claim, final Date value, final String otherClaim, final Date otherValue) throws JOSEException {
        if (value != null) {
            if (value.before(otherValue)) {
                throw new JOSEException("Optional claim '" + claim + "' " + value + " must be equal or after " + otherClaim + " " + otherValue);
            }
        }
    }

    private static void after(final String claim, final Date value, final String otherClaim, final Date otherValue) throws JOSEException {
        if (value == null) {
            throw new JOSEException("Required claim '" + claim + "' cannot be null");
        } else if ((otherValue != null) && (!value.after(otherValue))) {
            throw new JOSEException("Required claim '" + claim + "' " + value + " must be after " + otherClaim + " " + otherValue);
        }
    }

    private static void before(final String claim, final Date value, final String otherClaim, final Date otherValue) throws JOSEException {
        if (value != null) {
            if (!value.before(otherValue)) {
                throw new JOSEException("Optional claim '" + claim + "' " + value + " must be before " + otherClaim + " " + otherValue);
            }
        }
    }

    private static void notBlank(final String claim, final String value) throws JOSEException {
        if (value != null) {
            if (value.isBlank()) {
                throw new JOSEException("Optional claim '" + claim + "' cannot be blank");
            }
        }
    }

    private static void match(final String claim, final String value, final String targetValue) throws JOSEException {
        if ((targetValue != null) && (!value.equals(targetValue))) {
            throw new JOSEException("Claim '" + claim + "' " + value + " must match '" + targetValue + "'");
        }
    }

    private static void contains(final String claim, final List<String> value, final String targetValue) throws JOSEException {
        if ((targetValue != null) && (!value.contains(targetValue))) {
            throw new JOSEException("Claim '" + claim + "' " + value + " must contain '" + targetValue + "'");
        }
    }

    public static List<String> scopeList(final String scope) {
        return scope == null ? null : StringUtil.split(scope, " ");
    }

    @SuppressWarnings({"unchecked"})
    private static List<String> audList(final Object audObj) throws JOSEException {
        if (audObj == null) {
            throw new JOSEException("Required claim 'aud' cannot be null");
        } else if (audObj instanceof String audString) {
            return List.of(audString);
        } else if (audObj instanceof List<?> audLst) {
            for (final Object aud : audLst) {
                if ((aud != null) && (!(aud instanceof String))) {
                    throw new JOSEException("Required claim 'aud' must be List<String> but contains " + aud.getClass().getCanonicalName());
                }
            }
            return (List<String>) audLst;
        }
        throw new JOSEException("Required claim 'aud' must be a String or List<String>");
    }
}
