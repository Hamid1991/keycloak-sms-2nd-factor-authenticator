package com.alliander.keycloak.authenticator.data;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ConfigParam {

	@JsonProperty("key")
	private String key;
	
	@JsonProperty("value")
	private String value;

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}
	
	
}