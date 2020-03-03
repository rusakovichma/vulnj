package com.guthub.rusakovichma.vulnj.actuator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.annotation.PostConstruct;
import java.net.MalformedURLException;
import java.net.URL;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = SecurityConfiguration.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@RunWith(SpringJUnit4ClassRunner.class)
class ActuatorAuthorizationSecurityTest {

    @LocalServerPort
    private int port;

    private static final TestRestTemplate anonymousUser = new TestRestTemplate();

    private static final TestRestTemplate ordinaryUser = new TestRestTemplate("user", "password1");
    private static final TestRestTemplate adminUser = new TestRestTemplate("admin", "password2");

    private String actuatorUrl;

    @PostConstruct
    public void postConstruct() throws MalformedURLException {
        actuatorUrl = new URL(String.format("http://localhost:%d/actuator", port)).toString();
    }

    @Test
    void anonymousUserAuthorizationTest() throws Exception {
        ResponseEntity<String> anonymResponse = anonymousUser.exchange(actuatorUrl, HttpMethod.GET, null, String.class);
        assertThat(anonymResponse.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
    }

    @Test
    void ordinaryUserAuthorizationTest() throws Exception {
        ResponseEntity<String> ordinaryUserResponse = ordinaryUser.exchange(actuatorUrl, HttpMethod.GET, null, String.class);
        assertThat(ordinaryUserResponse.getStatusCode(), is(HttpStatus.FORBIDDEN));
    }

    @Test
    void adminUserAuthorizationTest() throws Exception {
        ResponseEntity<String> adminResponse = adminUser.exchange(actuatorUrl, HttpMethod.GET, null, String.class);
        assertThat(adminResponse.getStatusCode(), is(HttpStatus.OK));
    }

}