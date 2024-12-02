package com.github.justincranford.springs.server.authentication.client.service;

import com.github.justincranford.springs.server.authentication.client.token.ClientNameSecretAuthenticatedToken;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.TextCodec;
import com.github.justincranford.springs.util.jwt.JwkSetUtil;
import com.github.justincranford.springs.util.jwt.JwsDelegatingDecrypt;
import com.github.justincranford.springs.util.jwt.JwsDelegatingVerify;
import com.github.justincranford.springs.util.jwt.JwtContentUtil;
import com.github.justincranford.springs.util.jwt.JwtEncryptUtil;
import com.github.justincranford.springs.util.jwt.JwtSignUtil;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;

@Service
@Slf4j
public class JwtIssuerService {
    private String issuer;
    private List<String> audiences;
    private Duration duration;
    private LinkedHashSet<String> scopes;
    private JWKSet jwkSet;
    private JwsDelegatingVerify jwsDelegatingVerify;
    private JwsDelegatingDecrypt jwsDelegatingDecrypt;

    @PostConstruct
    public void postConstruct() {
        this.issuer = TextCodec.HEX_UC_STRICT.encodeToString(SecureRandomUtil.randomBytes(8));
        this.audiences = List.of(TextCodec.HEX_UC_STRICT.encodeToString(SecureRandomUtil.randomBytes(8)));
        this.duration = Duration.ofMinutes(15);
        this.scopes = new LinkedHashSet<>(List.of("ROLE_client"));
        this.jwkSet = JwkSetUtil.generateSet(Duration.ofHours(1), 1, 1, 1, 1, 1, 1, 1);
        this.jwsDelegatingVerify = new JwsDelegatingVerify(this.jwkSet);
        this.jwsDelegatingDecrypt = new JwsDelegatingDecrypt(this.jwkSet);
    }

    public JWT issue(@NotNull final ClientNameSecretAuthenticatedToken clientNameSecretAuthenticatedToken) throws JOSEException {
        @NotNull final String clientName = clientNameSecretAuthenticatedToken.getClientDetails().name();
        @NotNull final JWTClaimsSet jwtClaimsSet = JwtContentUtil.jwtClaimsSet(this.issuer, this.audiences, clientName, this.duration, this.scopes);
        return issue(jwtClaimsSet);
    }

    public JWT issue(final JWTClaimsSet jwtClaimsSet) throws JOSEException {
        final JWK randomJwk = SecureRandomUtil.randomListElement(this.jwkSet.getKeys());
        if (randomJwk.getAlgorithm() instanceof JWSAlgorithm jwsAlgorithm) {
            final JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm).type(JOSEObjectType.JWT).keyID(randomJwk.getKeyID()).build();
            final JWSSigner jwsSigner = JwtSignUtil.jwsSigner(randomJwk);
            return JwtSignUtil.sign(jwsHeader, jwtClaimsSet, jwsSigner);
        } else if (randomJwk.getAlgorithm() instanceof JWEAlgorithm jweAlgorithm) {
            final JWEHeader    jweHeader    = new JWEHeader.Builder(jweAlgorithm, EncryptionMethod.A256GCM).type(JOSEObjectType.JWT).keyID(randomJwk.getKeyID()).build();
            final JWEEncrypter jweEncrypter = JwtEncryptUtil.jweEncrypter(randomJwk, jweAlgorithm);
            return JwtEncryptUtil.encrypt(jweHeader, jwtClaimsSet, jweEncrypter);
        }
        throw new IllegalStateException("Unsupported JWK from JWKSet");
    }

    public JWT authenticate(final JWT jwt) {
        if (jwt instanceof SignedJWT signedJWT) {
            try {
                final SignedJWT authenticateJwt = this.jwsDelegatingVerify.verify(signedJWT);
                log.trace("SignedJWT authenticated ok.");
                return authenticateJwt;
            } catch (JOSEException e) {
                log.trace("SignedJWT verify exception.", e);
                throw new BadCredentialsException("SignedJWT verify exception."); // TODO Specific exception
            }
        } else if (jwt instanceof EncryptedJWT encryptedJWT) {
            try {
                final EncryptedJWT authenticateJWT = this.jwsDelegatingDecrypt.verify(encryptedJWT);
                log.trace("EncryptedJWT authenticated ok.");
                return authenticateJWT;
            } catch (JOSEException | BadCredentialsException e) {
                log.trace("EncryptedJWT decrypt exception.", e);
                throw new BadCredentialsException("EncryptedJWT decrypt exception."); // TODO Specific exception
            }
        } else if (jwt instanceof PlainJWT) {
            log.trace("PlainJWT not supported.");
            throw new BadCredentialsException("PlainJWT not supported."); // TODO Specific exception
        }
        log.trace("Unknown type JWT not supported.");
        throw new BadCredentialsException("Unknown type JWT not supported."); // TODO Specific exception
    }
}
