package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll();
                } )

                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic()
                .and().csrf().disable();

        //h2 console config
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
//        return NoOpPasswordEncoder.getInstance();
//        return new LdapShaPasswordEncoder();
//        return new StandardPasswordEncoder();
//        return new BCryptPasswordEncoder();
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

//    @Autowired
//    JpaUserDetailsService jpaUserDetailsService;

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder());

//        auth.inMemoryAuthentication()
//                .withUser("spring")
//                .password("{bcrypt}$2a$10$qLzjuHiYnmhejnlOgJV3dOBv1zwLXVGPwyi2jjxSAOEkKkPMJNpna")
//                .roles("ADMIN")
//                .and()
//                .withUser("user")
//                .password("{sha256}53e775451903393fcfba3af1808046a21f670df9262c83b59ca34904bb2ba5ec87fad1aa3aca9329")
//                .roles("USER")
//                .and()
//                .withUser("scott")
//                .password("{ldap}{SSHA}9yr9ceXrqWriJ7kDeHyOLiPBQsJbLGpaZGmt9g==")
//                .roles("CUSTOMER");
//    }

    //    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);
//    }


}
