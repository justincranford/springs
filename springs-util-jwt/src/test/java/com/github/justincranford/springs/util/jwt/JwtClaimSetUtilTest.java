package com.github.justincranford.springs.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwtClaimSetUtilTest {
    public abstract static class UT {
        private static Stream<JWTClaimsSet.Builder> validJwtClaimsSets() {
            return Stream.of(
                allClaims(),
                allClaims().jwtID(null),
                allClaims().notBeforeTime(null),
                allClaims().claim("nonce", null),
                allClaims().claim("scope", null),
                allClaims().jwtID(null).notBeforeTime(null).claim("nonce", null).claim("scope", null)
            );
        }
        private static JWTClaimsSet.Builder allClaims() {
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
    }

    @Nested
    public class Valid extends UT {
        @ParameterizedTest
        @MethodSource("validJwtClaimsSets")
        void allClaims(final JWTClaimsSet.Builder builder) throws JOSEException, ParseException {
            final JWTClaimsSet jwtClaimsSet = builder.build();
            assertTrue(JwtClaimSetUtil.validate(jwtClaimsSet, "targetIssuer", "targetAudience", "targetSubject"));
        }
        @Nested
        public class Issuer extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void mismatchIssIgnored(final JWTClaimsSet.Builder builder) throws JOSEException, ParseException {
                final JWTClaimsSet jwtClaimsSet = builder.subject("wrongIssuer").build();
                assertTrue(JwtClaimSetUtil.validate(jwtClaimsSet));
            }
        }

        @Nested
        public class Audience extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void mismatchSubIgnored(final JWTClaimsSet.Builder builder) throws JOSEException, ParseException {
                final JWTClaimsSet jwtClaimsSet = builder.subject("wrongSubject").build();
                assertTrue(JwtClaimSetUtil.validate(jwtClaimsSet));
            }
        }

        @Nested
        public class Subject extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void mismatchSubIgnored(final JWTClaimsSet.Builder builder) throws JOSEException, ParseException {
                final JWTClaimsSet jwtClaimsSet = builder.subject("wrongSubject").build();
                assertTrue(JwtClaimSetUtil.validate(jwtClaimsSet));
            }
        }

        @Nested
        public class Scope extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullScope(final JWTClaimsSet.Builder builder) throws ParseException, JOSEException {
                final JWTClaimsSet jwtClaimsSet = builder.claim("scope", null).build();
                assertTrue(JwtClaimSetUtil.validate(jwtClaimsSet));
            }
        }
    }

    @Nested
    public class Invalid {
        @Nested
        public class Issuer extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullIss(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.issuer(null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'iss' cannot be null", joseException.getMessage(), joseException.getMessage());
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void blankIss(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.issuer(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'iss' cannot be blank", joseException.getMessage(), joseException.getMessage());
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void mismatchIssEnforced(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.issuer("wrongIssuer").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet, "targetIssuer", null, null));
                assertEquals("Claim 'iss' wrongIssuer must match 'targetIssuer'", joseException.getMessage(), joseException.getMessage());
            }
        }

        @Nested
        public class Audience extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullAudString(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience((String) null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullAudList(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience((List<String>) null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void blankAudString(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot contain blank values", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void emptyAudList(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience(Collections.emptyList()).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot be empty", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void audListNullElement(final JWTClaimsSet.Builder builder) {
                final List<String> listNullElement = new ArrayList<>(1);
                listNullElement.add(null);
                final JWTClaimsSet jwtClaimsSet = builder.audience(listNullElement).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot contain null values", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void audListBlankElement(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience(List.of(" ")).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' cannot contain blank values", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            @SuppressWarnings({"unchecked", "rawtypes"})
            void audListNonStringElement(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience((List) List.of(1)).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'aud' must be List<String> but contains java.lang.Integer", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void mismatchAudEnforced(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.audience(Collections.singletonList("wrongAudience")).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet, null, "targetAudience", null));
                assertEquals("Claim 'aud' [wrongAudience] must contain 'targetAudience'", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Subject extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullSub(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.subject(null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'sub' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void blankSub(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.subject(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'sub' cannot be blank", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void mismatchSubEnforced(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.subject("wrongSubject").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet, null, null, "targetSubject"));
                assertEquals("Claim 'sub' wrongSubject must match 'targetSubject'", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Jti extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void blankJti(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.jwtID(" ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Optional claim 'jti' cannot be blank", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Nonce extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void blankNonce(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.claim("nonce", " ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Optional claim 'nonce' cannot be blank", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Scope extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void blankScope(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.claim("scope", " ").build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'scope' cannot be empty", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }
        }

        @Nested
        public class Dates extends UT {
            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullExp(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.expirationTime(null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'exp' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }

            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nullIat(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder.issueTime(null).build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertEquals("Required claim 'iat' cannot be null", joseException.getMessage(), printExceptionBeforeSupplyMessage(joseException));
            }

            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void iatAfterNow(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder
                    .issueTime(new Date(System.currentTimeMillis() + 10000L))
                    .notBeforeTime(new Date(System.currentTimeMillis() + 10000L))
                    .expirationTime(new Date(System.currentTimeMillis() + 60000L))
                    .build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertTrue(joseException.getMessage().contains("cannot be equal or after"), printExceptionBeforeSupplyMessage(joseException));
            }

            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void expBeforeIat(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder
                    .issueTime(new Date())
                    .notBeforeTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() - 10000L))
                    .build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertTrue(joseException.getMessage().contains("must be after"), printExceptionBeforeSupplyMessage(joseException));
            }

            @ParameterizedTest
            @MethodSource("validJwtClaimsSets")
            void nbfBeforeIat(final JWTClaimsSet.Builder builder) {
                final JWTClaimsSet jwtClaimsSet = builder
                    .issueTime(new Date())
                    .notBeforeTime(new Date(System.currentTimeMillis() - 10000L))
                    .expirationTime(new Date(System.currentTimeMillis() + 60000L))
                    .build();
                final JOSEException joseException = assertThrows(JOSEException.class, () -> JwtClaimSetUtil.validate(jwtClaimsSet));
                assertTrue(joseException.getMessage().contains("must be equal or after"), printExceptionBeforeSupplyMessage(joseException));
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
