package com.github.rusakovichma.zerothreats;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class ToolLauncher {

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(ToolLauncher.class, args);
        run.registerShutdownHook();
    }

}
