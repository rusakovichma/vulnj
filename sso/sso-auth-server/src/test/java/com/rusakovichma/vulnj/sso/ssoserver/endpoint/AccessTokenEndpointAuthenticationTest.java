package com.rusakovichma.vulnj.sso.ssoserver.endpoint;

import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Mockito.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Mockito.*;

import org.apache.commons.codec.binary.Base64;
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

    // ~ Methods
    // ========================================================================================================

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();

        UsernamePasswordAuthenticationToken clienaAppRequest = new UsernamePasswordAuthenticationToken(
                "foo", "bar");

        clienaAppRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
        Authentication clientAppAuth = new UsernamePasswordAuthenticationToken("foo", "bar",
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
        request.addHeader("Authorization", "Basic Zm9vOmJhcg==");
        request.setServletPath("/oauth/token");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
                .isEqualTo("foo");
    }

}
