package com.github.justincranford.springs.service.webauthn.authenticate.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter
//	@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder
@SuppressWarnings({"nls", "hiding"})
public class AuthenticationRequest {
	private final boolean success = true;
	private final String requestId;
	private final String sessionToken;
	private final AssertionRequest request;
	private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
	private final Optional<String> username;
	private final Actions actions;

	public AuthenticationRequest(
		@NotNull String sessionToken,
		@NotNull AssertionRequest request,
		@NotNull Actions actions
	) {
		this.requestId = sessionToken;
		this.sessionToken = sessionToken;
		this.request = request;
		this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
		this.username = request.getUsername();
		this.actions = actions;
	}

	@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//	@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	public static class Actions {
		public final URL finish;

		public Actions(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.finish = URI.create(url + slash + "finish").toURL();
		}
	}
}
