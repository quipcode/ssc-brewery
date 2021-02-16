package guru.sfg.brewery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication
public class SfgBreweryUiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SfgBreweryUiApplication.class, args);
    }

}