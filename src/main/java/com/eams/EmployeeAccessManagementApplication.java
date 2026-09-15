package com.eams;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class EmployeeAccessManagementApplication {

    public static void main(String[] args) {
        SpringApplication.run(EmployeeAccessManagementApplication.class, args);
    }
}
