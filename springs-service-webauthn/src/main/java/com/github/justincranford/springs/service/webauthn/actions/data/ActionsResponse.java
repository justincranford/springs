package com.github.justincranford.springs.service.webauthn.actions.data;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

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
@SuppressWarnings({"nls"})
public final class ActionsResponse {
	public final Actions actions;
	public final Info info;

	public ActionsResponse(final String url) throws MalformedURLException {
		this.actions = new Actions(url);
		this.info = new Info(url);
	}

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//		@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	public final class Actions {
		public final URL authenticate;
		public final URL deleteAccount;
		public final URL deregister;
		public final URL register;

		public Actions(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.authenticate = URI.create(url + slash + "authenticate").toURL();
			this.deleteAccount = URI.create(url + slash + "delete-account").toURL();
			this.deregister = URI.create(url + slash + "action/deregister").toURL();
			this.register = URI.create(url + slash + "register").toURL();
		}
	}

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//		@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	public final class Info {
		public final URL version;

		public Info(final String url) throws MalformedURLException {
			final String slash = url.endsWith("/") ? "" : "/";
			this.version = URI.create(url + slash + "version").toURL();
		}
	}
}
