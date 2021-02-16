package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import guru.sfg.brewery.security.google.Google2faFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final PersistentTokenRepository persistentTokenRepository;
    private final Google2faFilter google2faFilter;
    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(google2faFilter, SessionManagementFilter.class);

        http.cors().and()
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll();
                } )

                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin(loginConfigurer -> {
                    loginConfigurer
                            .loginProcessingUrl("/login")
                            .loginPage("/").permitAll()
                            .successForwardUrl("/")
                            .defaultSuccessUrl("/")
                            .failureUrl("/?error");
                })
                .logout(logoutConfigurer -> {
                    logoutConfigurer
                            .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                            .logoutSuccessUrl("/?logout")
                            .permitAll();
                })
                .httpBasic()
                .and().csrf().ignoringAntMatchers("/h2-console/**", "/api/**")
                .and()
                    .rememberMe()
                    .tokenRepository(persistentTokenRepository)
                    .userDetailsService(userDetailsService);
//                .rememberMe()
//                .key("sfg-key")
//                .userDetailsService(userDetailsService);

        //h2 console config
        http.headers().frameOptions().sameOrigin();


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
