package com.github.justincranford.springs.service.webauthn.authenticate.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

//@Accessors(fluent = true)
@AllArgsConstructor(onConstructor = @__(@JsonCreator))
@NoArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter(onMethod = @__(@JsonProperty))
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder(toBuilder=true)
@SuppressWarnings({"nls", "hiding"})
public class AuthenticationRequest {
	@Builder.Default
	private boolean success = true;
	private String requestId;
	private String sessionToken;
	private AssertionRequest request;
	private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
	private Optional<String> username;
	private Actions actions;

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

	//@Accessors(fluent = true)
	@AllArgsConstructor(onConstructor = @__(@JsonCreator))
	@NoArgsConstructor(onConstructor = @__(@JsonCreator))
	@Getter(onMethod = @__(@JsonProperty))
	@Setter(onMethod = @__(@JsonProperty))
	@ToString
	@EqualsAndHashCode(callSuper = false)
	@Builder(toBuilder=true)
	public static class Actions {
		public URL finish;

		public Actions(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.finish = URI.create(url + slash + "finish").toURL();
		}
	}
}
