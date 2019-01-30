package com.example.spboottest.config;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;


@Configuration
@EnableOAuth2Client
public class SecConfig extends WebSecurityConfigurerAdapter {
    private static final Logger log = LoggerFactory.getLogger(SecConfig.class);


    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .cors().and()
                .authorizeRequests()
                .antMatchers("/greeting",
                        "/login").permitAll()
                .anyRequest().authenticated().and()
                .logout().permitAll().logoutSuccessUrl("/")
                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint());;
    }
    private AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
            // You can use a lambda here
            @Override
            public void commence(HttpServletRequest aRequest, HttpServletResponse aResponse,
                                 AuthenticationException aAuthException) throws IOException, ServletException {
                aResponse.sendRedirect( "/login");
            }
        };
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD",
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // setAllowCredentials(true) is important, otherwise:
        // The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
        configuration.setAllowCredentials(false);
        // setAllowedHeaders is important! Without it, OPTIONS preflight request
        // will fail with 403 Invalid CORS request
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type","*"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    private Filter ssoFilter() {
        OAuth2ClientAuthenticationProcessingFilter kkFilter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        OAuth2RestTemplate keycloakTemplate = new OAuth2RestTemplate(keycloak(), oauth2ClientContext);
        kkFilter.setRestTemplate(keycloakTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(kcResource().getUserInfoUri(), keycloak().getClientId());
        tokenServices.setRestTemplate(keycloakTemplate);
        kkFilter.setTokenServices(tokenServices);
        return kkFilter;
    }

    @Bean
    @ConfigurationProperties("keycloak.client")
    public AuthorizationCodeResourceDetails keycloak() {

        log.info("Getting resource from application yaml");
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("keycloak.resource")
    public ResourceServerProperties kcResource() {
        return new ResourceServerProperties();
    }

    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }
}
