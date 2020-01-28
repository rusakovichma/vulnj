package com.rusakovichma.vulnj.csrf.controller;

import com.rusakovichma.vulnj.csrf.config.WebSecurityConfig;
import com.rusakovichma.vulnj.csrf.repository.RedisCsrfTokenRepository;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.client.RestTemplate;
import redis.embedded.RedisServer;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@IntegrationTest
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = WebSecurityConfig.class)
@WebAppConfiguration
public class SensitiveInfoControllerIntegrationTest {

    private static final String URL = "http://localhost:8080/";

    private RedisServer redisServer;

    private static final RestTemplate anonymous = new TestRestTemplate();

    private static final RestTemplate user1 = new TestRestTemplate("user1", "password1");
    private static final RestTemplate user2 = new TestRestTemplate("user2", "password2");

    @Before
    public void setup() throws Exception {
        redisServer = RedisServer.builder()
                .port(6379)
                .setting("maxmemory 128M") //maxheap 128M
                .build();
        redisServer.start();
    }

    @After
    public void tearDown() throws Exception {
        redisServer.stop();
    }

    //@Test
    public void thatInfoIsAccessible() {
        ResponseEntity<String> response = anonymous.getForEntity(URL + "sensitiveInfo", String.class);
        assertThat(response.getStatusCode(), is(HttpStatus.OK));
        assertThat(response.getBody(), is(SensitiveInfoController.DEFAULT_SENSITIVE_INFO));
    }

    //@Test
    public void thatLoginIsInaccessibleWithoutCredentials() {
        ResponseEntity<String> response = anonymous.getForEntity(URL + "token", String.class);
        assertThat(response.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
    }

    //    @Test
//    @DirtiesContext
    public void thatLoginIsAccessibleWithCredentials() {
        ResponseEntity<String> response = user1.getForEntity(URL + "token", String.class);
        assertThat(response.getStatusCode(), is(HttpStatus.OK));
        assertThat(response.getBody(), is(TokenController.CSRF_TOKEN_MESSAGE));
        assertThat(response.getHeaders(), Matchers.hasKey(RedisCsrfTokenRepository.CSRF_HEADER_NAME));
    }

    //    @Test
//    @DirtiesContext
    public void thatUpdateInfoIsInaccessibleWithoutCsrfToken() {
        ResponseEntity<String> putResponse = user1.exchange(URL + "sensitiveInfo", HttpMethod.PUT, null, String.class);
        assertThat(putResponse.getStatusCode(), is(HttpStatus.FORBIDDEN));
        assertThat(putResponse.getBody(), containsString("Expected CSRF token not found"));

        ResponseEntity<String> infoResponse = anonymous.getForEntity(URL + "sensitiveInfo", String.class);
        assertThat(infoResponse.getBody(), is(SensitiveInfoController.DEFAULT_SENSITIVE_INFO));
    }

    //    @Test
//    @DirtiesContext
    public void thatUpdateInfoIsInaccessibleWithCsrfTokenAndNoCredentials() {
        ResponseEntity<String> loginResponse = anonymous.getForEntity(URL + "token", String.class);
        String csrfToken = loginResponse.getHeaders().getFirst(RedisCsrfTokenRepository.CSRF_HEADER_NAME);

        HttpHeaders headers = new HttpHeaders();
        headers.add(RedisCsrfTokenRepository.CSRF_HEADER_NAME, csrfToken);

        final String newInfo = "Some new info with repository";

        ResponseEntity<String> response = anonymous.exchange(URL + "sensitiveInfo", HttpMethod.PUT, new HttpEntity<>(newInfo, headers), String.class);
        assertThat(response.getStatusCode(), is(HttpStatus.FORBIDDEN));

        ResponseEntity<String> infoResponse = anonymous.getForEntity(URL + "sensitiveInfo", String.class);
        assertThat(infoResponse.getBody(), is(SensitiveInfoController.DEFAULT_SENSITIVE_INFO));
    }

    @Test
    @DirtiesContext
    public void thatUpdateInfoIsAccessibleWithCsrfTokenAndCredentials() throws Exception {
        ResponseEntity<String> loginResponse = user1.getForEntity(URL + "token", String.class);
        String csrfToken = loginResponse.getHeaders().getFirst(RedisCsrfTokenRepository.CSRF_HEADER_NAME);

        HttpHeaders headers = new HttpHeaders();
        headers.add(RedisCsrfTokenRepository.CSRF_HEADER_NAME, csrfToken);

        final String newInfo = "Some new info with repository";
        ResponseEntity<String> response = user1.exchange(URL + "sensitiveInfo", HttpMethod.PUT, new HttpEntity<>(newInfo, headers), String.class);
        assertThat(response.getStatusCode(), is(HttpStatus.OK));
        assertThat(response.getBody(), is("sensitiveInfo updated"));

        ResponseEntity<String> infoResponse = anonymous.getForEntity(URL + "sensitiveInfo", String.class);
        assertThat(infoResponse.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
    }

    //@Test
    //@DirtiesContext
    public void thatUpdateInfoWithUser2CsrfTokenAndCredentials() {
        ResponseEntity<String> loginResponse1 = user1.getForEntity(URL + "token", String.class);

        ResponseEntity<String> attackerLoginResponse = user2.getForEntity(URL + "sensitiveInfo", String.class);
        String csrfTokenAttackers = attackerLoginResponse.getHeaders().getFirst(RedisCsrfTokenRepository.CSRF_HEADER_NAME);

        HttpHeaders headers = new HttpHeaders();
        headers.add(RedisCsrfTokenRepository.CSRF_HEADER_NAME, csrfTokenAttackers);

        final String newInfo = "Some new info with repository";
        ResponseEntity<String> response = user1.exchange(URL + "sensitiveInfo", HttpMethod.PUT, new HttpEntity<>(newInfo, headers), String.class);
        assertThat(response.getStatusCode(), is(HttpStatus.OK));
        assertThat(response.getBody(), is("sensitiveInfo updated"));

        ResponseEntity<String> infoResponse = anonymous.getForEntity(URL + "info", String.class);
        assertThat(infoResponse.getBody(), is(newInfo));
    }

}