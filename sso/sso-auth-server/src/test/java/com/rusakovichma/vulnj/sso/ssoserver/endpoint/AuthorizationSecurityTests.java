package com.rusakovichma.vulnj.sso.ssoserver.endpoint;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.web.bind.support.SimpleSessionStatus;
import org.springframework.web.servlet.ModelAndView;

import static com.rusakovichma.vulnj.sso.ssoserver.endpoint.util.AuthorizationRequestUtils.getAuthorizationRequest;
import static org.junit.Assert.assertEquals;


public class AuthorizationSecurityTests {

    private static final String AUTHORIZATION_REQUEST_ATTR_NAME = "authorizationRequest";

    private AuthorizationEndpoint endpoint = new AuthorizationEndpoint();

    private HashMap<String, Object> model = new HashMap<>();

    private SimpleSessionStatus sessionStatus = new SimpleSessionStatus();

    private UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken("user", "password",
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

    private BaseClientDetails client;

    @Before
    public void init() throws Exception {
        client = new BaseClientDetails();
        client.setRegisteredRedirectUri(Collections.singleton("http://clientapp:8082/clientApp/login"));
        client.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
        endpoint.setClientDetailsService(clientId -> client);
        endpoint.setTokenGranter((grantType, tokenRequest) -> null);
        endpoint.setRedirectResolver(new DefaultRedirectResolver());
        endpoint.afterPropertiesSet();
    }

    @Test
    public void testRightAuthorizationRequest() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "clientAppId", "http://clientapp:8082/clientApp/login", "HG6owT", "user_info", Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);

        ModelAndView modelAndView = endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);

        final String viewExpected = "forward:/oauth/confirm_access";
        assertEquals(viewExpected, modelAndView.getViewName());
    }

    @Test(expected = RedirectMismatchException.class)
    public void testAuthorizationRequestOpenRedirectAttack() throws Exception {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "clientAppId", "http://attackerapp:8082/clientApp/login", "HG6owT", "user_info", Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);

        endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
    }


    @Test
    public void testCSRFValidationAuthServerSide() {
        AuthorizationRequest authorizationRequest = getAuthorizationRequest(
                "clientAppId", "http://clientapp:8082/clientApp/login", null, "user_info", Collections.singleton("code"));
        model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);

        endpoint.authorize(model, authorizationRequest.getRequestParameters(), sessionStatus, principal);
    }

}
