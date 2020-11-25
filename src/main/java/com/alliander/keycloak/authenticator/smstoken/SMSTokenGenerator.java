package com.alliander.keycloak.authenticator.smstoken;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

import com.alliander.keycloak.authenticator.KeycloakSmsAuthenticator;
import com.alliander.keycloak.authenticator.SMSAuthenticatorContstants;
import com.alliander.keycloak.authenticator.SMSAuthenticatorUtil;
import com.alliander.keycloak.authenticator.data.SMSTokenInput;
import com.alliander.keycloak.authenticator.data.SMSTokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SMSTokenGenerator {
	
    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticator.class);
	
	private static AuthenticatorConfigModel config;
	
	public SMSTokenGenerator(AuthenticatorConfigModel config) {
		this.config = config;
	}

	public String generateSMSToken() throws URISyntaxException, ClientProtocolException, IOException {
		String generatedToken = "";
		CloseableHttpClient  httpClient = HttpClients.createDefault();
		URI tokenUrl = new URI(getTokenURL());
		ObjectMapper mapper = new ObjectMapper();
		String body = mapper.writeValueAsString(createTokenInput());
		HttpPost httpPost = new HttpPost(tokenUrl);
		httpPost.setEntity(new StringEntity(body));
		httpPost.setHeader("Content-type", SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_TOKEN_CONTENT_TYPE));
		CloseableHttpResponse response = httpClient.execute(httpPost);
		StatusLine sl = response.getStatusLine();
        if(sl.getStatusCode() != 200) {
            logger.error("SMS token is not generated " + sl.getStatusCode() +  " - " + sl.getReasonPhrase());
        } else {
    		ObjectMapper responseMapper =new ObjectMapper();
        	SMSTokenResponse tokenResponse = responseMapper.readValue(response.getEntity().getContent(), SMSTokenResponse.class);
        	generatedToken = tokenResponse.getJwt();
        }
        response.close();
		return generatedToken;
	}
	
	private static String getTokenURL() {
		return SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_TOKEN_URL);
	}
	
	private static SMSTokenInput createTokenInput() {
		SMSTokenInput smsTokenInput = new SMSTokenInput();
		smsTokenInput.setClientId(
				SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CLIENTID));
		smsTokenInput.setSecret(
				SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_SECRET));
		smsTokenInput.setExpiresIn(Long.getLong(
				SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_TOKEN_TTL)));
		return smsTokenInput;
	}
}
