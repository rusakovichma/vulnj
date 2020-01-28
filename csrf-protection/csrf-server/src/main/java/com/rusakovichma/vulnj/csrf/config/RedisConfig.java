package com.rusakovichma.vulnj.csrf.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.embedded.Redis;
import redis.embedded.RedisServer;

@Configuration
public class RedisConfig {

    @Bean(initMethod = "start", destroyMethod = "stop")
    public Redis redis() {
        return RedisServer.builder()
                .port(6379)
                .setting("maxmemory 128M") //maxheap 128M
                .build();
    }

}
