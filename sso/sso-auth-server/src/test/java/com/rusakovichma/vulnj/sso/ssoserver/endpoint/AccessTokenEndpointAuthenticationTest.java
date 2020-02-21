package com.rusakovichma.vulnj.sso.ssoserver.endpoint;

import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Mockito.*;

import static org.assertj.core.api.Assertions.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class AccessTokenEndpointAuthenticationTest {

    private BasicAuthenticationFilter filter;
    private AuthenticationManager authenticationManager;


    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();

        UsernamePasswordAuthenticationToken clienaAppRequest = new UsernamePasswordAuthenticationToken(
                "clientAppId", "clientAppSecret");

        clienaAppRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
        Authentication clientAppAuth = new UsernamePasswordAuthenticationToken("clientAppId", "clientAppSecret",
                AuthorityUtils.createAuthorityList());

        authenticationManager = mock(AuthenticationManager.class);
        when(authenticationManager.authenticate(clienaAppRequest)).thenReturn(clientAppAuth);
        when(authenticationManager.authenticate(not(eq(clienaAppRequest)))).thenThrow(
                new BadCredentialsException(""));

        filter = new BasicAuthenticationFilter(authenticationManager,
                new BasicAuthenticationEntryPoint());
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testOAuthTokenEndpointClientAppAuthentication() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        //Client - 'clientApp', password - 'clientAppSecret'
        request.addHeader("Authorization", "Basic Y2xpZW50QXBwSWQ6Y2xpZW50QXBwU2VjcmV0");
        request.setServletPath("/oauth/token");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
                .isEqualTo("clientAppId");
    }

}
