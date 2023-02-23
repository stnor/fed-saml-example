package com.example.fedsamlexample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class FedSamlExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(FedSamlExampleApplication.class, args);
    }

}
