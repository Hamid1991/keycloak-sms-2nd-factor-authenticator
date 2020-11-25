package com.alliander.keycloak.authenticator;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.UserCredentialStoreManager;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;

import com.alliander.keycloak.authenticator.data.ConfigParam;
import com.alliander.keycloak.authenticator.data.MapConfig;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by joris on 18/11/2016.
 */
public class SMSAuthenticatorUtil {

    private static Logger logger = Logger.getLogger(SMSAuthenticatorUtil.class);

    public static String getAttributeValue(UserModel user, String attributeName) {
        String result = null;
        List<String> values = user.getAttribute(attributeName);
        if(values != null && values.size() > 0) {
            result = values.get(0);
        }

        return result;
    }


    public static CredentialModel getCredentialValue(AuthenticationFlowContext context, String credentialName) {
        UserCredentialStoreManager credentialStore = new UserCredentialStoreManager(context.getSession());
        CredentialModel result = null;
        List<CredentialModel> creds = credentialStore.getStoredCredentials(context.getRealm(), context.getUser());
        for (CredentialModel cred : creds) {
            if(cred.getType().equals(credentialName)) {
               return cred;
            }
        }

        return result;
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName) {
        return getConfigString(config, configName, null);
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName, String defaultValue) {

        String value = defaultValue;

        if (config.getConfig() != null) {
            // Get value
            value = config.getConfig().get(configName);
        }

        return value;
    }

    public static Long getConfigLong(AuthenticatorConfigModel config, String configName) {
        return getConfigLong(config, configName, null);
    }

    public static Long getConfigLong(AuthenticatorConfigModel config, String configName, Long defaultValue) {

        Long value = defaultValue;

        if (config.getConfig() != null) {
            // Get value
            Object obj = config.getConfig().get(configName);
            try {
                value = Long.valueOf((String) obj); // s --> ms
            } catch (NumberFormatException nfe) {
                logger.error("Can not convert " + obj + " to a number.");
            }
        }

        return value;
    }
    
    public static Map<String, String> getMapConfig(AuthenticatorConfigModel config, String configName){
    	Map<String, String> map = new HashMap<>(); 
    	if(config.getConfig() != null) {
    		Object obj = config.getConfig().get(configName);
    		try {
    			map = parameters(obj);
    		} catch (Exception e) {
    			 logger.error("Can not convert " + obj + " to a Map.");
    		}
    	}
    	return map;
    }
    
    public static Map<String, String> parameters(Object obj) {
        Map<String, String> map = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        ConfigParam[] mapConfig = null;
        try {
			mapConfig = mapper.readValue(obj.toString(), ConfigParam[].class);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        for(ConfigParam param : mapConfig) {
        	map.put(param.getKey(), param.getValue());
        }
        return map;
    }
}