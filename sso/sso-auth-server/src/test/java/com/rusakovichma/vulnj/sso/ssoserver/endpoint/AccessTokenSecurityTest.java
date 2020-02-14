package com.rusakovichma.vulnj.sso.ssoserver.endpoint;

import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import static org.junit.Assert.*;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.junit.After;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenSecurityTest {

    @Mock
    private TokenGranter tokenGranter;

    @Mock
    private OAuth2RequestFactory authorizationRequestFactory;

    @Mock
    private ClientDetailsService clientDetailsService;

    private String clientId = "foo";
    private String clientSecret = "bar";

    private BaseClientDetails clientDetails = new BaseClientDetails();

    private TokenEndpoint endpoint;

    private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
            Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));

    private TokenRequest createFromParameters(Map<String, String> parameters) {
        TokenRequest request = new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
                parameters.get(OAuth2Utils.GRANT_TYPE));
        return request;
    }

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();

    private MockFilterChain chain = new MockFilterChain();

    private AuthenticationManager authenticationManager = Mockito.mock(AuthenticationManager.class);

    private BaseClientDetails client = new BaseClientDetails("foo", null, "user_info", "authorization_code",
            "ROLE_CLIENT");

    private ClientDetailsService stubDetailsService = new ClientDetailsService() {
        public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
            return client;
        }
    };

    private OAuth2RequestFactory oAuth2RequestFactory = new DefaultOAuth2RequestFactory(stubDetailsService);

    @Before
    public void init() {
        endpoint = new TokenEndpoint();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
        endpoint.setClientDetailsService(clientDetailsService);
        clientDetails.setClientId(clientId);

        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("foo", "bar", AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_CLIENT")));
    }

    @After
    public void close() {
        SecurityContextHolder.clearContext();
    }


    @Test
    public void testGetAccessTokenWithScope() throws HttpRequestMethodNotSupportedException {

        HashMap<String, String> parameters = new HashMap<>();

        parameters.put("client_id", clientId);
        parameters.put("client_secret", clientSecret);
        parameters.put("scope", "user_info");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "S1CuNG");

        request.setParameters(parameters);

        Mockito.when(authenticationManager.authenticate(Mockito.<Authentication>any())).thenReturn(
                new UsernamePasswordAuthenticationToken("user", "password", AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_USER")));
        TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);

        try {
            filter.doFilter(request, response, chain);
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertTrue(authentication.isAuthenticated());

        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("1b989b5e-a94c-45d9-b59b-d6bd1b0018e5");
        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);

        when(tokenGranter.grant(eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = Mockito.any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        OAuth2AccessToken body = response.getBody();
        assertEquals(body, expectedToken);

        System.out.println("ACCESS TOKEN: " + body.getValue());

        assertTrue("Wrong body: " + body, body.getTokenType() != null);
        assertTrue("Scope of token request not cleared", captor.getValue().getScope().isEmpty());
    }

}
