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
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.HttpRequestMethodNotSupportedException;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenSecurityTest {

    @Mock
    private TokenGranter tokenGranter;

    @Mock
    private OAuth2RequestFactory authorizationRequestFactory;

    @Mock
    private ClientDetailsService clientDetailsService;

    private String clientId = "clientAppId";
    private BaseClientDetails clientDetails = new BaseClientDetails();

    private TokenEndpoint endpoint;

    private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("clientAppId", null, Collections.EMPTY_LIST);

    private TokenRequest createFromParameters(Map<String, String> parameters) {
        TokenRequest request = new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
                parameters.get(OAuth2Utils.GRANT_TYPE));
        return request;
    }

    @Before
    public void init() {
        endpoint = new TokenEndpoint();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
        endpoint.setClientDetailsService(clientDetailsService);
        clientDetails.setClientId(clientId);
    }

    @Test
    public void testGetAccessTokenWithScope() throws HttpRequestMethodNotSupportedException {

        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", "clientAppId");
        parameters.put("redirect_uri", "http://localhost:8082/clientApp/login");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "S3SN5s");
        parameters.put("scope", "user_info");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("d1402cfd-7e4f-4d3e-962e-8d1188dadf93");
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
    }

}
