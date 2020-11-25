package com.alliander.keycloak.authenticator;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.UserCredentialStoreManager;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.PasswordUserCredentialModel;
import org.w3c.dom.html.HTMLHtmlElement;

import com.alliander.keycloak.authenticator.data.SMSTokenResponse;
import com.alliander.keycloak.authenticator.smstoken.SMSTokenGenerator;

/**
 * Created by joris on 11/11/2016.
 */
public class KeycloakSmsAuthenticator implements Authenticator {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticator.class);

    public static final String CREDENTIAL_TYPE = "sms_validation";

    private static enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }


    public void authenticate(AuthenticationFlowContext context) {
        logger.debug("authenticate called ... context = " + context);

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String mobileNumberAttribute = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_USR_ATTR_MOBILE);
        if(mobileNumberAttribute == null) {
            logger.error("Mobile number attribute is not configured for the SMS Authenticator.");
            Response challenge =  context.form()
                    .setError("Mobile number can not be determined.")
                    .createForm("sms-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }

        String mobileNumber = SMSAuthenticatorUtil.getAttributeValue(context.getUser(), mobileNumberAttribute);
        if(mobileNumber != null) {
            // The mobile number is configured --> send an SMS


            long nrOfDigits = SMSAuthenticatorUtil.getConfigLong(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
            logger.debug("Using nrOfDigits " + nrOfDigits);


            long ttl = SMSAuthenticatorUtil.getConfigLong(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s

            logger.debug("Using ttl " + ttl + " (s)");

            String code = getSmsCode(nrOfDigits);

            storeSMSCode(context, code); // s --> ms
            try {
				if (sendSmsCode(mobileNumber, code, context.getAuthenticatorConfig())) {
				    Response challenge = context.form().createForm("sms-validation.ftl");
				    context.challenge(challenge);
				} else {
				    Response challenge =  context.form()
				            .setError("SMS could not be sent.")
				            .createForm("sms-validation-error.ftl");
				    context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
				    return;
				}
			} catch (URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        } else {
            // The mobile number is NOT configured --> complain
            Response challenge =  context.form()
                    .setError("Missing mobile number")
                    .createForm("sms-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
            return;
        }
    }


    public void action(AuthenticationFlowContext context) {
        logger.debug("action called ... context = " + context);
        CODE_STATUS status = validateCode(context);
        Response challenge = null;
        switch (status) {
            case EXPIRED:
                challenge =  context.form()
                        .setError("code is expired")
                        .createForm("sms-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;

            case INVALID:
                if(context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.CONDITIONAL ||
                        context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    logger.debug("Calling context.attempted()");
                    context.attempted();
                } else if(context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    challenge =  context.form()
                            .setError("badCode")
                            .createForm("sms-validation.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                } else {
                    // Something strange happened
                    logger.warn("Undefined execution ...");
                }
                break;

            case VALID:
                context.success();
                break;

        }
    }

    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeSMSCode(AuthenticationFlowContext context, String code) {
    	PasswordPolicy passwordPolicy = context.getRealm().getPasswordPolicy();
    	PasswordHashProvider hash = context.getSession().getProvider(PasswordHashProvider.class, PasswordPolicy.HASH_ALGORITHM_DEFAULT);
    	PasswordCredentialModel smsCredentialModel = hash.encodedCredential(code, passwordPolicy.getHashIterations());
    	smsCredentialModel.setType(SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE);
    	smsCredentialModel.setCreatedDate(Time.currentTimeMillis());
    	storeCredential(context, smsCredentialModel);
    }


	protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
		CODE_STATUS result = CODE_STATUS.INVALID;
		logger.debug("validateCode called ... ");
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String enteredCode = formData.getFirst(SMSAuthenticatorContstants.ANSW_SMS_CODE);
		CredentialModel expectedCodeCredential = SMSAuthenticatorUtil.getCredentialValue(context,
				SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE);
		long ttl = SMSAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				SMSAuthenticatorContstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L);
		long expiryTime = expectedCodeCredential.getCreatedDate() + ttl * 100;

		logger.debug("Expected code = " + expectedCodeCredential + "    entered code = " + enteredCode);

		if (expectedCodeCredential != null) {
			result = verifySMScode(context, enteredCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
			long now = new Date().getTime();

			logger.debug("Valid code expires in " + (expiryTime - now) + " ms");
			if (result == CODE_STATUS.VALID) {
				if (expiryTime < now) {
					logger.debug("Code is expired !!");
					result = CODE_STATUS.EXPIRED;
				}
			}
		}
		logger.debug("result : " + result);
		return result;
	}

    public boolean requiresUser() {
        logger.debug("requiresUser called ... returning true");
        return true;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("configuredFor called ... session=" + session + ", realm=" + realm + ", user=" + user);
        boolean result = true;
        logger.debug("... returning "  +result);
        return result;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("setRequiredActions called ... session=" + session + ", realm=" + realm + ", user=" + user);
    }

    public void close() {
        logger.debug("close called ...");
    }


    private String getSmsCode(long nrOfDigits) {
        if(nrOfDigits < 1) {
            throw new RuntimeException("Nr of digits must be bigger than 0");
        }

        double maxValue = Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        Random r = new Random();
        long code = (long)(r.nextFloat() * maxValue);
        return Long.toString(code);
    }

    private boolean sendSmsCode(String mobileNumber, String code, AuthenticatorConfigModel config) throws URISyntaxException {
        // Send an SMS
        logger.debug("Sending " + code + "  to mobileNumber " + mobileNumber);

        String smsUrl = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_URL);
        String smsUsr = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CLIENTID);
        String smsPwd = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_SECRET);

        String proxyUrl = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_PROXY_URL);
        String proxyUsr = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_PROXY_USERNAME);
        String proxyPwd = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_PROXY_PASSWORD);
        String contentType = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_CONTENT_TYPE);

        CloseableHttpClient httpClient = null;
        try {
            URL smsURL = (smsUrl != null && smsUrl.length() > 0) ? new URL(smsUrl) : null;
            URL proxyURL = (proxyUrl != null && proxyUrl.length() > 0) ? new URL(proxyUrl) : null;

            if(smsURL == null) {
                logger.error("SMS gateway URL is not configured.");
                return false;
            }
            

            CredentialsProvider credsProvider;
            if(SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.AUTH_METHOD_INMESSAGE)) {
                credsProvider = getCredentialsProvider(null, null, proxyUsr, proxyPwd, smsURL, proxyURL);
            } else if (SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.AUTH_METHOD_BASIC)){
                credsProvider = getCredentialsProvider(smsUsr, smsPwd, proxyUsr, proxyPwd, smsURL, proxyURL);
            } else {
            	credsProvider = getCredentialsProvider(smsUsr, smsPwd, null, null, smsURL, proxyURL);
            }

            HttpHost target = new HttpHost(smsURL.getHost(), smsURL.getPort(), smsURL.getProtocol());
            HttpHost proxy = (proxyURL != null) ? new HttpHost(proxyURL.getHost(), proxyURL.getPort(), proxyURL.getProtocol()) : null;

           if (SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.BEARER)) {
            	httpClient = HttpClients.custom().build();
            } else {
                httpClient = HttpClients.custom()
                        .setDefaultCredentialsProvider(credsProvider)
                        .build();
            }

            RequestConfig requestConfig;
                requestConfig = RequestConfig.custom()
                        .setProxy(proxy)
                        .build();

            String httpMethod = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_METHOD);
            String smsText = createMessage(code, mobileNumber, config);
            if(httpMethod.equals(HttpMethod.GET)) {
            	Map<String, String> params = SMSAuthenticatorUtil.getMapConfig(config, SMSAuthenticatorContstants.QUERY_PARAMS);
				replaceValues(params, mobileNumber, smsText);
				URI uri = new URI(smsUrl.toString() + generateUri(params));

                HttpGet httpGet = new HttpGet(uri);
                httpGet.setConfig(requestConfig);
                if(SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.BEARER)) {
                    SMSTokenGenerator tokenGenerator = new SMSTokenGenerator(config);
        			String generatedToken =tokenGenerator.generateSMSToken();
                	httpGet.addHeader("Authorization", SMSAuthenticatorContstants.BEARER+" "+generatedToken);
                }
                if(isNotEmpty(contentType)) {
                    httpGet.addHeader("Content-type", contentType);
                }

                logger.debug("Executing request " + httpGet.getRequestLine() + " to " + target + " via " + proxy);

                CloseableHttpResponse response = httpClient.execute(target, httpGet);
                StatusLine sl = response.getStatusLine();
                response.close();
                if(sl.getStatusCode() != 200) {
                    logger.error("SMS code for " + mobileNumber + " could not be sent: " + sl.getStatusCode() +  " - " + sl.getReasonPhrase());
                }
                return sl.getStatusCode() == 200;

			} else if (httpMethod.equals(HttpMethod.POST)) {
				Map<String, String> params = SMSAuthenticatorUtil.getMapConfig(config, SMSAuthenticatorContstants.QUERY_PARAMS);
				replaceValues(params, mobileNumber, smsText);
				URI uri = new URI(smsUrl.toString() + generateUri(params));
				HttpPost httpPost = new HttpPost(uri);
				httpPost.setConfig(requestConfig);
				if(SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.BEARER)) {
                    SMSTokenGenerator tokenGenerator = new SMSTokenGenerator(config);
        			String generatedToken =tokenGenerator.generateSMSToken();
        			httpPost.addHeader("Authorization", SMSAuthenticatorContstants.BEARER+" "+generatedToken);
                }
				if (isNotEmpty(contentType)) {
					httpPost.addHeader("Content-type", contentType);
				}

				HttpEntity entity = new ByteArrayEntity(smsText.getBytes("UTF-8"));
				httpPost.setEntity(entity);

				CloseableHttpResponse response = httpClient.execute(httpPost);
				StatusLine sl = response.getStatusLine();
				response.close();
				if (sl.getStatusCode() != 200) {
					logger.error("SMS code for " + mobileNumber + " could not be sent: " + sl.getStatusCode() + " - "
							+ sl.getReasonPhrase());
				}
				return sl.getStatusCode() == 200;
			}
            return true;
        } catch (IOException e) {
            logger.error(e);
            return false;
        } finally {
            if(httpClient != null) {
                try {
                    httpClient.close();
                } catch(IOException ignore) {
                    // Ignore ...
               }
            }
        }
    }


    private String getPath(String mobileNumber, URL smsURL, String smsText) throws UnsupportedEncodingException {
        String path = smsURL.getPath();
        if(smsURL.getQuery() != null && smsURL.getQuery().length() > 0) {
            path += smsURL.getQuery();
        }
        path = path.replaceFirst("\\{message\\}", URLEncoder.encode(smsText, "UTF-8"));
        path = path.replaceFirst("\\{phonenumber\\}", URLEncoder.encode(mobileNumber, "UTF-8"));
        return path;
    }

    private CredentialsProvider getCredentialsProvider(String smsUsr, String smsPwd, String proxyUsr, String proxyPwd, URL smsURL, URL proxyURL) {
        CredentialsProvider credsProvider = new BasicCredentialsProvider();

        // If defined, add BASIC Authentication parameters
        if (isNotEmpty(smsUsr) && isNotEmpty(smsPwd)) {
            credsProvider.setCredentials(
                    new AuthScope(smsURL.getHost(), smsURL.getPort()),
                    new UsernamePasswordCredentials(smsUsr, smsPwd));

        }

        // If defined, add Proxy Authentication parameters
        if (isNotEmpty(proxyUsr) && isNotEmpty(proxyPwd)) {
            credsProvider.setCredentials(
                    new AuthScope(proxyURL.getHost(), proxyURL.getPort()),
                    new UsernamePasswordCredentials(proxyUsr, proxyPwd));

        }
        return credsProvider;
    }

    private String createMessage(String code, String mobileNumber, AuthenticatorConfigModel config) {
        String text = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_TEXT);
        text = text.replaceAll("%sms-code%", code);
        text = text.replaceAll("%phonenumber%", mobileNumber);

//        if(SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.AUTH_METHOD_INMESSAGE)) {
//            String smsUsr = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CLIENTID);
//            String smsPwd = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_SECRET);
//
//            text = text.replaceAll("%user%", smsUsr);
//            text = text.replaceAll("%password%", smsPwd);
//        }

        return text;
    }

    private boolean isNotEmpty(String s) {
        return (s != null && s.length() > 0);
    }
    
    private String generateUri(Map<String, String> params) throws UnsupportedEncodingException {
    	String uri ="?";
    	for(String key : params.keySet()) {
    		boolean isEncoded = params.get(key).contains(" ");
    		String paramKey = key;
    		String paramValue = !isEncoded ? params.get(key) : URLEncoder.encode(params.get(key),"UTF-8");
    		uri = uri +paramKey +"="+paramValue+"&";
    	}
    	return uri.substring(0, uri.length()-1);
    }
    
    private CredentialModel storeCredential(AuthenticationFlowContext context, PasswordCredentialModel credential) {
    	CredentialModel credentialModel;
    	UserCredentialStoreManager credentialStore = new UserCredentialStoreManager(context.getSession());
    	CredentialModel credentialValue = SMSAuthenticatorUtil.getCredentialValue(context, credential.getType());
    	if(credentialValue == null) {
    		credentialModel = credentialStore.createCredential(context.getRealm(), context.getUser(), credential);
    	} else {
    		credential.setId(credentialValue.getId());
    		credentialStore.updateCredential(context.getRealm(), context.getUser(), credential);
    		credentialModel = credential;
    	}
    	return credentialModel;
    }
    
	private boolean verifySMScode(AuthenticationFlowContext context, String smsCode) {
		boolean isVerifiedSMScode = false;
		UserCredentialModel toValidate = UserCredentialModel.password(smsCode);
		toValidate.setType(SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE);
		if (isValidSmsCode(context, context.getRealm(), context.getUser(), toValidate)) {
			return true;
		}
		return isVerifiedSMScode;
	}
    
	private boolean isValidSmsCode(AuthenticationFlowContext context, RealmModel realm, UserModel user,
			CredentialInput input) {

		if (!(input instanceof UserCredentialModel)) {
			logger.debug("Expected instance of UserCredentialModel for CredentialInput");
			return false;

		}
		if (input.getChallengeResponse() == null) {
			logger.debugv("Input password was null for user {0} ", user.getUsername());
			return false;
		}
		PasswordCredentialModel password = PasswordCredentialModel.createFromCredentialModel(
				SMSAuthenticatorUtil.getCredentialValue(context, SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE));
		if (password == null) {
			logger.debugv("No password cached or stored for user {0} ", user.getUsername());
			return false;
		}
		PasswordHashProvider hash = context.getSession().getProvider(PasswordHashProvider.class,
				password.getPasswordCredentialData().getAlgorithm());
		if (hash == null) {
			logger.debugv("PasswordHashProvider {0} not found for user {1} ",
					password.getPasswordCredentialData().getAlgorithm(), user.getUsername());
			return false;
		}
		if (!hash.verify(input.getChallengeResponse(), password)) {
			logger.debugv("Failed password validation for user {0} ", user.getUsername());
			return false;
		}
		PasswordPolicy policy = realm.getPasswordPolicy();
		if (policy == null) {
			return true;
		}
		hash = context.getSession().getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
		if (hash == null) {
			return true;
		}
		if (hash.policyCheck(policy, password)) {
			return true;
		}

		PasswordCredentialModel newPassword = hash.encodedCredential(input.getChallengeResponse(),
				policy.getHashIterations());
		newPassword.setId(password.getId());
		newPassword.setCreatedDate(password.getCreatedDate());
		newPassword.setUserLabel(password.getUserLabel());
		UserCredentialStoreManager credentialStore = new UserCredentialStoreManager(context.getSession());
		credentialStore.updateCredential(realm, user, newPassword);

		UserCache userCache = context.getSession().userCache();
		if (userCache != null) {
			userCache.evict(realm, user);
		}

		return true;
	}
	
	private void replaceValues(Map<String, String> params, String mobileNumber, String smsText) {
		for(String key : params.keySet()) {
			if(params.get(key).contains("%message%")) {
				params.replace(key, params.get(key).replaceAll("%message%", smsText));
			}
			if(params.get(key).contains("%phonenumber%")) {
				params.replace(key, params.get(key).replaceAll("%phonenumber%", mobileNumber));
			}
		}
	}

}