package com.rusakovichma.vulnj.csrf.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@ComponentScan(basePackages = "com.rusakovichma.vulnj.csrf")
@EnableAutoConfiguration
@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CsrfTokenRepository tokenRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().and()
                .csrf().csrfTokenRepository(tokenRepository).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/sensitiveInfo").hasAnyRole("USER", "ADMIN")
                .antMatchers(HttpMethod.PUT, "/sensitiveInfo").hasAnyRole("ADMIN")
                .anyRequest().hasAnyRole("USER", "ADMIN");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password("password1").roles("USER")
                .and()
                .withUser("admin").password("password2").roles("ADMIN");
    }

}