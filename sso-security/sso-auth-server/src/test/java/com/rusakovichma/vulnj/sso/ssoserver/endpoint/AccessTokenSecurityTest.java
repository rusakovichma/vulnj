package com.rusakovichma.vulnj.sso.ssoserver.endpoint;

import org.junit.After;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import static org.junit.Assert.*;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.*;

import static org.assertj.core.api.Assertions.*;

import java.security.Principal;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenSecurityTest {

    private final static String CLIENT_APP_ID = "clientAppId";
    private final static String CLIENT_APP_SECRET = "clientAppSecret";

    @Mock
    private TokenGranter tokenGranter;

    @Mock
    private OAuth2RequestFactory authorizationRequestFactory;

    @Mock
    private ClientDetailsService clientDetailsService;

    private BaseClientDetails clientDetails = new BaseClientDetails();

    private TokenEndpoint endpoint;

    private Principal clientAuthentication = new UsernamePasswordAuthenticationToken(CLIENT_APP_ID, null, Collections.EMPTY_LIST);

    private BasicAuthenticationFilter filter;
    private AuthenticationManager authenticationManager;

    private TokenRequest createFromParameters(Map<String, String> parameters) {
        TokenRequest request = new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
                parameters.get(OAuth2Utils.GRANT_TYPE));
        return request;
    }

    private void initTokenEndpoint(){
        endpoint = new TokenEndpoint();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
        endpoint.setClientDetailsService(clientDetailsService);
        clientDetails.setClientId(CLIENT_APP_ID);
    }

    private void initTokenEndpointAuthFilter(){
        SecurityContextHolder.clearContext();

        UsernamePasswordAuthenticationToken clienaAppRequest = new UsernamePasswordAuthenticationToken(
                CLIENT_APP_ID, CLIENT_APP_SECRET);

        clienaAppRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
        Authentication clientAppAuth = new UsernamePasswordAuthenticationToken(CLIENT_APP_ID, CLIENT_APP_SECRET,
                AuthorityUtils.createAuthorityList());

        authenticationManager = mock(AuthenticationManager.class);
        when(authenticationManager.authenticate(clienaAppRequest)).thenReturn(clientAppAuth);
        when(authenticationManager.authenticate(not(eq(clienaAppRequest)))).thenThrow(
                new BadCredentialsException(""));

        filter = new BasicAuthenticationFilter(authenticationManager,
                new BasicAuthenticationEntryPoint());
    }

    private void destroyTokenEndpointAuthContext(){
        SecurityContextHolder.clearContext();
    }

    @Before
    public void init() {
        initTokenEndpoint();
        initTokenEndpointAuthFilter();
    }

    @After
    public void clearContext() {
        destroyTokenEndpointAuthContext();
    }


    public void testOAuthTokenEndpointClientAppAuthentication(String clientAppId, String clientSecret) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        //Client - 'clientAppId', password - 'clientAppSecret'
        final String authEncoded = Base64.getEncoder().encodeToString(
                String.format("%s:%s", clientAppId, clientSecret).getBytes());
        request.addHeader("Authorization", String.format("Basic %s", authEncoded));
        request.setServletPath("/oauth/token");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
                .isEqualTo("clientAppId");
    }

    @Test
    public void testGetAccessTokenWithScope() throws Exception {

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", "clientAppId");
        parameters.put("client_secret", "clientAppSecret");
        parameters.put("redirect_uri", "http://localhost:8082/clientApp/login");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "S3SN5s");
        parameters.put("scope", "user_info");

        when(clientDetailsService.loadClientByClientId(CLIENT_APP_ID)).thenReturn(clientDetails);

        testOAuthTokenEndpointClientAppAuthentication(parameters.get("client_id"), parameters.get("client_secret"));

        final UUID accessToken = UUID.randomUUID();
        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken(accessToken.toString());
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
