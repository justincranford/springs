package com.github.justincranford.springs.util.jwt;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.util.List;
import java.util.Set;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
    public final class ParamsHelper {
        static JWTClaimsSet validJwtClaimsSet() {
            return JwtContentUtil.jwtClaimsSetBuilder(validIssuer(), validAudiences(), validSubject(), validDuration(), validScopes()).build();
        }
        static JWTClaimsSet invalidJwtClaimsSetExp() {
            return JwtContentUtil.jwtClaimsSetBuilder(validIssuer(), validAudiences(), validSubject(), invalidDuration(), validScopes()).build();
        }

        static String validIssuer() {
            return "iss-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8);
        }
        static List<String> validAudiences() {
            return List.of("aud-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8));
        }
        static String validSubject() {
            return "sub-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8);
        }
        static Set<String> validScopes() {
            return Set.of("scope-" + SecureRandomUtil.randomString(TextCodec.B64_STD, 8));
        }
        static Duration validDuration() {
            return Duration.ofHours(1);
        }
        static Duration invalidDuration() {
            return Duration.ofHours(-1);
        }
    }
