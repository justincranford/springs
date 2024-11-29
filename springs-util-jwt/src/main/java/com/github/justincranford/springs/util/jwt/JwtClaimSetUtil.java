package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static com.github.justincranford.springs.util.jwt.JwtContentUtil.scopeList;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public class JwtClaimSetUtil {
    public static boolean validateSyntax(final JWTClaimsSet claims) throws ParseException, JOSEException {
        try {
            final String       iss   = claims.getIssuer();
            final List<String> aud   = claims.getAudience();
            final String       sub   = claims.getSubject();
            final String       jti   = claims.getJWTID();
            final String       nonce = claims.getStringClaim("nonce");
            final Date         iat   = claims.getIssueTime();
            final Date         nbf   = claims.getNotBeforeTime();
            final Date         exp   = claims.getExpirationTime();
            final List<String> scope = scopeList(claims.getStringClaim("scope"));
            final Instant      now   = DateTimeUtil.now().toInstant();

            if ((iss == null) || (iss.isBlank())) {
                throw new JOSEException("Claim 'iss' is required and cannot be blank");
            } else if ((aud == null) || (aud.isEmpty())) {
                throw new JOSEException("Claim 'aud' is required and cannot be empty");
            } else if (aud.stream().anyMatch(a -> (a == null || a.isBlank()))) {
                throw new JOSEException("Claim 'aud' is required and cannot contain blank entries");
            } else if ((sub == null) || (sub.isBlank())) {
                throw new JOSEException("Claim 'sub' is required and cannot be blank");
            } else if ((jti != null) && (jti.isBlank())) {
                throw new JOSEException("Claim 'jti' is optional for unique JWT identification but cannot be blank");
            } else if ((nonce != null) && (nonce.isBlank())) {
                throw new JOSEException("Claim 'nonce' is optional for replay attack mitigation but cannot be blank");
            } else if ((iat == null) || (now.isBefore(iat.toInstant()))) {
                throw new JOSEException("Claim 'iat' is required and cannot be in the future");
            } else if ((nbf != null) && (nbf.toInstant().isBefore(iat.toInstant()))) {
                throw new JOSEException("Claim 'nbf' is optional but cannot be before iat");
            } else if ((exp != null) && (exp.toInstant().isBefore(iat.toInstant()))) {
                throw new JOSEException("Claim 'exp' is optional but cannot be before 'iat'");
            } else if ((nbf != null) && (exp != null) && exp.toInstant().isBefore(nbf.toInstant())) {
                throw new JOSEException("Claim 'nbf' and 'exp' are optional but 'nbf' cannot be after 'exp'");
            } else if ((exp == null) || (exp.toInstant().isBefore(now))) {
                throw new JOSEException("Claim 'exp' is required and must be in the future");
            } else if ((scope == null) || (scope.isEmpty())) {
                throw new JOSEException("Claim 'scope' is required and cannot be empty");
            } else if (scope.stream().anyMatch(s -> (s == null || s.isBlank()))) {
                throw new JOSEException("Claim 'scope' is required and cannot contain blank entries");
            }
            return true;
        } catch(Exception e) {
//            log.warn("Not valid", e);
            return false;
        }
    }

    public static boolean validateSemantics(final JWTClaimsSet claims, final String expectedIss, final String expectedAud) throws ParseException, JOSEException {
        final String       iss   = claims.getIssuer();
        final List<String> aud   = claims.getAudience();
        final String       sub   = claims.getSubject();
        final String       jti   = claims.getJWTID();
        final String       nonce = claims.getStringClaim("nonce");
        final Date         iat   = claims.getIssueTime();
        final Date         nbf   = claims.getNotBeforeTime();
        final Date         exp   = claims.getExpirationTime();
        final List<String> scope = claims.getStringListClaim("scope");
        final Instant      now   = DateTimeUtil.now().toInstant();

        if (!expectedIss.equals(iss)) {
            throw new JOSEException("Claim 'iss' does not match the expected value");
        } else if (!aud.contains(expectedAud)) {
            throw new JOSEException("Claim 'aud' does not contain the expected audience");
        } else if ((nbf != null) && (nbf.toInstant().isAfter(now))) {
            throw new JOSEException("Claim 'nbf' is in the future");
        } else if ((exp != null) && (exp.toInstant().isBefore(now))) {
            throw new JOSEException("JWT 'exp' is in the past");
        }
        return true;
    }

    public static boolean validateExpiration(JWTClaimsSet claims) {
        return claims.getExpirationTime().toInstant().isAfter(Instant.now());
    }

    public static boolean validateAudience(JWTClaimsSet claims, String expectedAudience) {
        return claims.getAudience().contains(expectedAudience);
    }

    public static boolean validateIssuer(JWTClaimsSet claims, String expectedIssuer) {
        return expectedIssuer.equals(claims.getIssuer());
    }
}
