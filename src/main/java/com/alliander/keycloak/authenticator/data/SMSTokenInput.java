package com.alliander.keycloak.authenticator.data;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SMSTokenInput {

	@JsonProperty("client_id")
	private String clientId;
	
	@JsonProperty("secret")
	private String secret;
	
	@JsonProperty("expires_in")
	private Long expiresIn;

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public Long getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(Long expiresIn) {
		this.expiresIn = expiresIn;
	}

}