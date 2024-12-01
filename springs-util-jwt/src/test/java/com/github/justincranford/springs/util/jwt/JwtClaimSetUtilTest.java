package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwtClaimSetUtilTest {
    private static JWTClaimsSet.Builder buildAllValidClaims() {
        final long now = System.currentTimeMillis();
        return new JWTClaimsSet.Builder()
           .issuer("targetIssuer")
           .audience(List.of("targetAudience", "otherAudience"))
           .subject("targetSubject")
           .jwtID("jti")
           .claim("nonce", "nonce")
           .claim("scope", "read write")
           .issueTime(new Date(now - 10000L)) // 10 seconds ago
           .notBeforeTime(new Date(now - 5000L)) // 5 seconds ago
           .expirationTime(new Date(now + 60000L)); // 5 seconds in the future
    }

    @Nested
    public class Valid {
        @Test
        void allClaims() throws JOSEException, ParseException {
            final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().build();
            assertTrue(JwtClaimSetUtil.validate(jwtClaimsSet, "targetIssuer", "targetAudience", "targetSubject"));
        }
        @Nested
        public class Issuer {
            @Test
            void mismatchIssIgnored() throws ParseException, JOSEException {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().subject("wrongIssuer").build();
                JwtClaimSetUtil.validate(jwtClaimsSet, null, null, null);
            }
        }

        @Nested
        public class Audience {
            @Test
            void mismatchSubIgnored() throws ParseException, JOSEException {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().subject("wrongSubject").build();
                JwtClaimSetUtil.validate(jwtClaimsSet, null, null, null);
            }
        }

        @Nested
        public class Subject {
            @Test
            void mismatchSubIgnored() throws ParseException, JOSEException {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().subject("wrongSubject").build();
                JwtClaimSetUtil.validate(jwtClaimsSet, null, null, null);
            }
        }
    }

    @Nested
    public class Invalid {
        @Nested
        public class Issuer {
            @Test
            void nullIss() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().issuer(null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'iss' cannot be null", joseException.getMessage(), joseException.getMessage());
            }
            @Test
            void blankIss() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().issuer(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'iss' cannot be blank", joseException.getMessage(), joseException.getMessage());
            }
            @Test
            void mismatchIssEnforced() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().issuer("wrongIssuer").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet, "targetIssuer", null, null));
                assertEquals("Claim 'iss' wrongIssuer must match 'targetIssuer'", joseException.getMessage(), joseException.getMessage());
            }
        }

        @Nested
        public class Audience {
            @Test
            void nullAud() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().audience((List<String>) null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @Test
            void emptyAud() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().audience(Collections.emptyList()).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot be empty", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @Test
            void mismatchAudEnforced() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().audience(Collections.singletonList("wrongAudience")).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet, null, "targetAudience", null));
                assertEquals("Claim 'aud' [wrongAudience] must contain 'targetAudience'", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Subject {
            @Test
            void nullSub() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().subject(null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'sub' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @Test
            void blankSub() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().subject(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'sub' cannot be blank", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @Test
            void mismatchSubEnforced() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().subject("wrongSubject").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet, null, null, "targetSubject"));
                assertEquals("Claim 'sub' wrongSubject must match 'targetSubject'", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Jti {
            @Test
            void blankJti() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().jwtID(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Optional claim 'jti' cannot be blank", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Nonce {
            @Test
            void blankNonce() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().claim("nonce", " ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Optional claim 'nonce' cannot be blank", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Scope {
            @Test
            void nullScope() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().claim("scope", null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'scope' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }

            @Test
            void blankScope() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().claim("scope", " ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'scope' cannot be empty", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Dates {
            @Test
            void iatAfterNow() {
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims().issueTime(new Date(System.currentTimeMillis() + 10000)).notBeforeTime(new Date(System.currentTimeMillis() + 10000)).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertTrue(joseException.getMessage().contains("cannot be equal or after"), printExceptionBeforeSupplyMessage(joseException));
            }

            @Test
            void expBeforeIat() {
                Date now = new Date();
                final JWTClaimsSet jwtClaimsSet = buildAllValidClaims()
                                                      .issueTime(new Date(now.getTime()))
                                                      .notBeforeTime(new Date(now.getTime()))
                                                      .expirationTime(new Date(now.getTime() - 10000)) // 10 seconds before
                                                      .build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertTrue(joseException.getMessage().contains("must be after"), printExceptionBeforeSupplyMessage(joseException));
            }
        }
    }

    private static Supplier<String> printExceptionBeforeSupplyMessage(final Exception exception) {
        return () -> {
            exception.printStackTrace();
            return exception.getMessage();
        };
    }
}
