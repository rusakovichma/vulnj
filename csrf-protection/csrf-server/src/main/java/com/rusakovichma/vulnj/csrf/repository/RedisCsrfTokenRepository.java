package com.rusakovichma.vulnj.csrf.repository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;
import redis.clients.jedis.Jedis;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

@Component
@DependsOn({"redis"})
public class RedisCsrfTokenRepository implements CsrfTokenRepository {

    private static final Logger log = LoggerFactory.getLogger(RedisCsrfTokenRepository.class);

    public static final String CSRF_PARAMETER_NAME = "_csrf";

    public static final String CSRF_HEADER_NAME = "X-CSRF-TOKEN";

    private final Jedis tokenRepository = new Jedis("localhost", 6379);

    public RedisCsrfTokenRepository() {
        log.info("Creating {}", RedisCsrfTokenRepository.class.getSimpleName());
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, createNewToken());
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        String key = getKey(request);
        if (key == null)
            return;

        if (token == null) {
            tokenRepository.del(key.getBytes());
        } else {
            tokenRepository.set(key.getBytes(), SerializationUtils.serialize(token));
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        String key = getKey(request);
        if (key != null) {
            byte[] tokenString = tokenRepository.get(key.getBytes());
            if (tokenString != null) {
                return (CsrfToken) SerializationUtils.deserialize(tokenString);
            }
        }
        return null;
    }

    private String getKey(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    private String createNewToken() {
        return UUID.randomUUID().toString();
    }
}
