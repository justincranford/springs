package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.ArrayList;
import java.util.List;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.StringUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public record HashInputs(
	@NotNull HashInputConstants hashInputConstants,
	@NotNull HashInputVariables hashInputVariables
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.hashInputVariables().canonicalBytes(), this.hashInputConstants().canonicalBytes());
	}

	public String encodeHashInputsAndHash(@NotEmpty final byte[] actualHashBytes) {
		final String actualHashInputsEncoded = this.encodeHashInputs();
		final String actualHashEncoded       = this.hashInputConstants().encode(actualHashBytes);
		if (actualHashInputsEncoded.isEmpty()) {
			return actualHashEncoded;
		}
		return actualHashInputsEncoded + this.hashInputConstants().encodeDecode().separators().parametersVsHash() + actualHashEncoded;
	}

	private String encodeHashInputs() {
		final List<Object> hashInputsValues = new ArrayList<>();
		if (this.hashInputConstants.encodeDecode().flags().encodeHashInputVariables()) {
			hashInputsValues.addAll(this.hashInputVariables.canonicalObjects(this.hashInputConstants));
		}
		if (this.hashInputConstants.encodeDecode().flags().encodeHashInputConstants()) {
			hashInputsValues.addAll(this.hashInputConstants.canonicalObjects());
		}
		return StringUtil.toString("", this.hashInputConstants.encodeDecode().separators().intraParameters(), "", hashInputsValues);
	}
}
