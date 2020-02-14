package com.rusakovichma.vulnj.sso.ssoserver.endpoint;

import static com.rusakovichma.vulnj.sso.ssoserver.endpoint.util.AuthorizationRequestUtils.unmodifiableMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.web.bind.support.SimpleSessionStatus;

import static com.rusakovichma.vulnj.sso.ssoserver.endpoint.util.AuthorizationRequestUtils.getAuthorizationRequest;


public class AuthorizationSecurityTests {

    private static final String AUTHORIZATION_REQUEST_ATTR_NAME = "authorizationRequest";
    private static final String ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME = "org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST";

    private AuthorizationEndpoint endpoint = new AuthorizationEndpoint();

    private HashMap<String, Object> model = new HashMap<String, Object>();

    private SimpleSessionStatus sessionStatus = new SimpleSessionStatus();

    private UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("foo", "bar",
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

    private BaseClientDetails client;

    @Before
    public void init() throws Exception {
        client = new BaseClientDetails();
        client.setRegisteredRedirectUri(Collections.singleton("https://anywhere.com"));
        client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "implicit"));
        endpoint.setClientDetailsService(new ClientDetailsService() {
            public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
                return client;
            }
        });
        endpoint.setTokenGranter(new TokenGranter() {
            public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
                return null;
            }
        });
        endpoint.setRedirectResolver(new DefaultRedirectResolver());
        endpoint.afterPropertiesSet();
    }

    @Test//(expected = InvalidRequestException.class)
    public void testApproveWithModifiedState() throws Exception {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "foo", "https://anywhere.com", "state-1234", "read", Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
        model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, unmodifiableMap(authorizationRequest));
        authorizationRequest.setState("state-5678");        // Modify authorization request
        Map<String, String> approvalParameters = new HashMap<String, String>();
        approvalParameters.put("user_oauth_approval", "true");
        endpoint.approveOrDeny(approvalParameters, model, sessionStatus, principal);
    }

    private class StubAuthorizationCodeServices implements AuthorizationCodeServices {
        private OAuth2Authentication authentication;

        public String createAuthorizationCode(OAuth2Authentication authentication) {
            this.authentication = authentication;
            return "thecode";
        }

        public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
            return authentication;
        }
    }

}
