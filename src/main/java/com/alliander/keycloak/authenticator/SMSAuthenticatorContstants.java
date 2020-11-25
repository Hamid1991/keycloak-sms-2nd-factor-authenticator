package com.alliander.keycloak.authenticator;

/**
 * Created by joris on 18/11/2016.
 */
public class SMSAuthenticatorContstants {
//    public static final String ATTR_MOBILE = "mobileNumber";
    public static final String ANSW_SMS_CODE = "smsCode";

    // Configurable fields
    public static final String CONF_PRP_USR_ATTR_MOBILE = "sms-auth.attr.mobile";
    public static final String CONF_PRP_SMS_TOKEN_TTL = "sms-auth.token.ttl";
    public static final String CONF_PRP_SMS_CODE_TTL = "sms-auth.code.ttl";
    public static final String CONF_PRP_SMS_CODE_LENGTH = "sms-auth.code.length";
    public static final String CONF_PRP_SMS_TEXT = "sms-auth.msg.text";

    public static final String CONF_PRP_SMS_TOKEN_URL = "sms-auth.sms.token.url";
    public static final String CONF_PRP_SMS_TOKEN_AUTHTYPE = "sms-auth.sms.token.authtype";
    public static final String CONF_PRP_SMS_TOKEN_METHOD = "sms-auth.sms.token.method";
    public static final String CONF_PRP_SMS_TOKEN_CONTENT_TYPE = "sms-auth.content.token.type";
    public static final String CONF_PRP_SMS_URL = "sms-auth.sms.url";
    public static final String CONF_PRP_SMS_METHOD = "sms-auth.sms.method";
    public static final String CONF_PRP_SMS_CLIENTID = "sms-auth.sms.username";
    public static final String CONF_PRP_SMS_SECRET = "sms-auth.sms.password";
    public static final String CONF_PRP_SMS_AUTHTYPE = "sms-auth.sms.authtype";
    public static final String CONF_PRP_CONTENT_TYPE = "sms-auth.content.type";

    public static final String CONF_PRP_PROXY_URL = "sms-auth.proxy.url";
    public static final String CONF_PRP_PROXY_USERNAME = "sms-auth.proxy.username";
    public static final String CONF_PRP_PROXY_PASSWORD = "sms-auth.proxy.password";

    // User credentials (used to persist the sent sms code + expiration time cluster wide)
    public static final String USR_CRED_MDL_SMS_CODE = "sms-auth.code";
    public static final String USR_CRED_MDL_SMS_EXP_TIME = "sms-auth.exp-time";

    // Authentication methods
    public static final String NO_AUTH = "No Auth";
    public static final String AUTH_METHOD_BASIC = "Basic authentication";
    public static final String AUTH_METHOD_INMESSAGE = "In message authentication";
    public static final String QUERY_PARAMS="sms-params";
    public static final String TOKEN_BODY = "token-body";
    public static final String BEARER = "Bearer";

}