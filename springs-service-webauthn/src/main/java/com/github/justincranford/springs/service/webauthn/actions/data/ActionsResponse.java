package com.github.justincranford.springs.service.webauthn.actions.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter
//@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder
@SuppressWarnings({"nls"})
public final class ActionsResponse {
	public final Actions actions;
	public final Info info;

	public ActionsResponse(final String url) throws MalformedURLException {
		final String slash = url.endsWith("/") ? "" : "/";
		this.actions = new Actions(url + slash);
		this.info    = new Info(url + slash);
	}

	@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//	@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	@Builder
	public static final class Actions {
		public final URL authenticate;
		public final URL deleteAccount;
		public final URL deregister;
		public final URL register;

		public Actions(final String url) throws MalformedURLException {
			this.authenticate  = URI.create(url + "authenticate").toURL();
			this.deleteAccount = URI.create(url + "delete-account").toURL();
			this.deregister    = URI.create(url + "action/deregister").toURL();
			this.register      = URI.create(url + "register").toURL();
		}
	}

	@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//	@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@Builder
	@EqualsAndHashCode(callSuper = false)
	public static final class Info {
		public final URL version;

		public Info(final String url) throws MalformedURLException {
			this.version = URI.create(url + "version").toURL();
		}
	}
}
