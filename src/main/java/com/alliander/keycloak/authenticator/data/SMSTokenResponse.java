package com.alliander.keycloak.authenticator.data;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SMSTokenResponse {
	
	@JsonProperty("jwt")
	private String jwt;
	
	@JsonProperty("token_type")
	private String tokenType;
	
	@JsonProperty("expires")
	private Long expires;

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	public String getTokenType() {
		return tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public Long getExpires() {
		return expires;
	}

	public void setExpires(Long expires) {
		this.expires = expires;
	}

}