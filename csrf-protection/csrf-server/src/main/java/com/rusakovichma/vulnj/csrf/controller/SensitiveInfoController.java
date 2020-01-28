package com.rusakovichma.vulnj.csrf.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
public class SensitiveInfoController {

    public static final String DEFAULT_SENSITIVE_INFO = "Default sensitive info";

    private String sensitiveInfo = DEFAULT_SENSITIVE_INFO;

    @ResponseBody
    @RequestMapping(value = "/sensitiveInfo")
    public ResponseEntity<String> getSensitiveInfo() {
        return new ResponseEntity<>(sensitiveInfo, HttpStatus.OK);
    }

    @ResponseBody
    @RequestMapping(value = "/sensitiveInfo", method = RequestMethod.PUT)
    public ResponseEntity<String> updateSensitiveInfo(@RequestBody String sensitiveInfo) {
        this.sensitiveInfo = sensitiveInfo;
        return new ResponseEntity<>("sensitiveInfo updated", HttpStatus.OK);
    }

}
