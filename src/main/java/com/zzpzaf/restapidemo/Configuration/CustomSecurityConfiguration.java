package com.zzpzaf.restapidemo.Configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class CustomSecurityConfiguration {

   
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;


    public CustomRequestHeaderTokenFilter customFilter() throws Exception {
        CustomRequestHeaderTokenFilter authFilter = new CustomRequestHeaderTokenFilter(authenticationConfiguration.getAuthenticationManager());
        authFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/auth/signin","GET"));
        return authFilter;
    }
    
    
    @Bean
    public SecurityFilterChain filterChain1(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .formLogin().disable()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeHttpRequests(authorize -> authorize
            .requestMatchers(HttpMethod.POST, "/auth/signup").permitAll()
            .requestMatchers("/auth/signin").authenticated()
            .requestMatchers("/users").hasRole("ADMIN")
            .requestMatchers("/items").hasAnyRole("ADMIN", "USER")
            .anyRequest().permitAll()
            )
            ;
        http.addFilter(customFilter());  
        return http.build();
    } 
}    

