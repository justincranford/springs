package com.github.justincranford.springs.service.webauthn.register.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter(onMethod = @__(@JsonProperty))
@Setter
//	@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder
@SuppressWarnings({"nls"})
public class RegistrationRequest {
	private final boolean success = true;
	private final UserIdentity userIdentity;
	private final String username;
	private final String displayName;
	private final String credentialNickname;
	private final String sessionToken;
	private final Request request;
	private final StartRegistrationActions actions;

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//		@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	@Builder
	public static class Request {
		@JsonInclude(JsonInclude.Include.NON_NULL)
		private final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
	}

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//		@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	public static class StartRegistrationActions {
		public final URL finish;

		public StartRegistrationActions(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.finish = URI.create(url + slash + "finish").toURL();
		}
	}
}
