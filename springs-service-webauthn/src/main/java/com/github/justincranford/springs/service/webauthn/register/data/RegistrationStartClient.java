package com.github.justincranford.springs.service.webauthn.register.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ResidentKeyRequirement;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

//@Accessors(fluent = true)
@AllArgsConstructor
@NoArgsConstructor
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode
@Builder(toBuilder=true)
public class RegistrationStartClient {
	@NotBlank private String username;
	@NotBlank private String displayName;
	@Nullable private String credentialNickname;
	@NotNull  private ResidentKeyRequirement residentKeyRequirement;
}
