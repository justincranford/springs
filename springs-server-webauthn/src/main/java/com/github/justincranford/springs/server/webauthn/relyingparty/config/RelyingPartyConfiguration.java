package com.github.justincranford.springs.server.webauthn.relyingparty.config;

import com.github.justincranford.springs.server.webauthn.credential.repository.CredentialRepositoryFacade;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.time.Clock;
import java.util.List;

@Configuration
@Import({CredentialRepositoryFacade.class})
@SuppressWarnings({"unused"})
public class RelyingPartyConfiguration {
	@Value("${server.address}")
	private String serverAddress;

	@Value("${webauthn.relyingParty.id}")
	private String webauthnRelyingPartyId;

	@Value("${webauthn.relyingParty.name}")
	private String webauthnRelyingPartyName;

	@Bean
	public RelyingPartyIdentity relyingPartyIdentity() {
		return RelyingPartyIdentity.builder()
		    .id(this.webauthnRelyingPartyId)
		    .name(this.webauthnRelyingPartyName)
		    .build();
	}

	@Bean
	public RelyingParty relyingParty(final RelyingPartyIdentity relyingPartyIdentity, final CredentialRepository credentialRepository) throws InvalidAppIdException {
		return RelyingParty.builder()
		    .identity(relyingPartyIdentity)
		    .credentialRepository(credentialRepository)
		    .appId(new AppId("https://" + this.serverAddress))
		    .preferredPubkeyParams(
		    	List.of(
	    			 PublicKeyCredentialParameters.EdDSA /** @see COSEAlgorithmIdentifier.EdDSA = -8 */
	    			,PublicKeyCredentialParameters.ES512 /** @see COSEAlgorithmIdentifier.ES512 = -36 */
	    			,PublicKeyCredentialParameters.ES384 /** @see COSEAlgorithmIdentifier.ES384 = -35 */
	    			,PublicKeyCredentialParameters.ES256 /** @see COSEAlgorithmIdentifier.ES256 = -7 */
	    			,PublicKeyCredentialParameters.RS512 /** @see COSEAlgorithmIdentifier.RS512 = -259 */
	    			,PublicKeyCredentialParameters.RS384 /** @see COSEAlgorithmIdentifier.RS384 = -258 */
	    			,PublicKeyCredentialParameters.RS256 /** @see COSEAlgorithmIdentifier.RS256 = -257 */
	    			,PublicKeyCredentialParameters.RS1   /** @see COSEAlgorithmIdentifier.RS1   = -65535 */
				)
    		)
		    .clock(Clock.systemUTC())
//		    .origins(Collections.singleton("https://" + this.serverAddress))
            .allowOriginPort(true)
            .allowOriginSubdomain(true)
//            .allowUntrustedAttestation(true)
//            .validateSignatureCounter(true)
            .build();
	}
}
