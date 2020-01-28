package com.rusakovichma.vulnj.csrf;

import org.junit.Assert;
import org.junit.Test;
import redis.clients.jedis.Jedis;
import redis.embedded.RedisServer;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class EmbeddedRedisServerTest {

    @Test
    public void thatEmbeddedRedisServerWorks() throws Exception {
        RedisServer redisServer = RedisServer.builder()
                .port(6379)
                .setting("maxmemory 128M") //maxheap 128M
                .build();
        assertFalse(redisServer.isActive());
        redisServer.start();
        assertTrue(redisServer.isActive());
        redisServer.stop();
        assertFalse(redisServer.isActive());
    }

    @Test
    public void thatJedisCanAccessEmbeddedServer() throws Exception {
        RedisServer redisServer = RedisServer.builder()
                .port(6379)
                .setting("maxmemory 128M") //maxheap 128M
                .build();
        redisServer.start();
        Jedis jedis = new Jedis("localhost", 6379);
        jedis.set("testKey", "testValue");
        Assert.assertThat(jedis.get("testKey"), is("testValue"));
        redisServer.stop();
    }

}
