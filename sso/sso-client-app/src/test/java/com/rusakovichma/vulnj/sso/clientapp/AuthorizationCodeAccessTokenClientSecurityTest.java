package com.rusakovichma.vulnj.sso.clientapp;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.UUID;

public class AuthorizationCodeAccessTokenClientSecurityTest {

    @Rule
    public ExpectedException expected = ExpectedException.none();

    private final UUID accessToken = UUID.randomUUID();

    private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

    private AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken(accessToken.toString());
        }
    };

    private AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();


    //1. User requests http://localhost:8082/clientApp/ and set DefaultOAuth2ClientContext.setPreservedState(state, preservedState),
    // where preservedState - current Client App URL
    //2. Client app requests Auth Serve http://localhost:8080/sso-server/oauth/authorize?client_id=clientAppId&redirect_uri=http://localhost:8082/clientApp/login&response_type=code&state=ch7NA7
    //3. User login at http://localhost:8080/sso-server/login
    //4. Auth Server redirects the user to http://localhost:8082/clientApp/login?code=f98YlR&state=ch7NA7
    //5. Client App validate if it CSRF
    //6. Client App removes the state DefaultOAuth2ClientContext.removePreservedState(state)
    //7. Client app retrieve access token directly from Auth Server and
    //8. Client app retrieve information about the user directly from Auth Server with scope user_info
    //9. Client app redirects the user to preservedState URL
    @Test
    public void testCSRFvalidationClientApp() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();

        request.setAuthorizationCode("S3SN5s");
        request.setStateKey("any_key"); // or request.setStateKey(null);
        //No preserved state - symptom of CSRF
        request.setPreservedState(null);

        resource.setAccessTokenUri("http://auth-server/oauth/token");
        resource.setPreEstablishedRedirectUri("https://clientapp.com");

        expected.expect(InvalidRequestException.class);
        expected.expectMessage("Possible CSRF detected - state parameter was required but no state could be found");
        provider.obtainAccessToken(resource, request);
    }

}
