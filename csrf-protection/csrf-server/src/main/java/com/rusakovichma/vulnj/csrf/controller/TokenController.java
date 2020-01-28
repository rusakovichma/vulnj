package com.rusakovichma.vulnj.csrf.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TokenController {

    public static final String CSRF_TOKEN_MESSAGE = "repository token";

    @ResponseBody
    @RequestMapping(value = "/token")
    public ResponseEntity<String> token(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        HttpHeaders headers = new HttpHeaders();
        headers.add(token.getHeaderName(), token.getToken());
        return new ResponseEntity<>(CSRF_TOKEN_MESSAGE, headers, HttpStatus.OK);
    }

}
