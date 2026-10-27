package org.togo.authentication.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SpringSecurity {

    @Value("${cors.local.host}")
    private String localHost;
    @Value("${cors.cloud.host}")
    private String cloudHostDashboard;
    @Value("${cors.cloud.login}")
    private String cloudHostLogin;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository
    ) throws Exception {
        http.cors(cors-> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(req->
                req
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                        "/oauth/**", "/fb/**", "/linkedin/**", "/jwt/**", "/gToken/**"
                ).permitAll()
                        .anyRequest().authenticated()
        )
                .oauth2Login(
                        oauth2->
                                oauth2
                                        .authorizationEndpoint(authorization -> authorization.authorizationRequestResolver(
                                        customAuthorizationRequestResolver(clientRegistrationRepository)
                                ))
                                .defaultSuccessUrl(cloudHostLogin+"/?auth=callback", true)
                                        .failureUrl(cloudHostLogin)
                );
            return http.build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of(localHost,
                cloudHostDashboard, cloudHostLogin));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    private OAuth2AuthorizationRequestResolver customAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization"
                );

        resolver.setAuthorizationRequestCustomizer(customizer -> {
            // Remove nonce specifically for problematic registration IDs (e.g., linkedin)
            OAuth2AuthorizationRequest request = customizer.build();
            Map<String, Object> additionalParameters = new HashMap<>(request.getAdditionalParameters());
            additionalParameters.remove("nonce");

            customizer.additionalParameters(additionalParameters);
            customizer.attributes(attributes -> attributes.remove("nonce"));
        });

        return resolver;
    }
}
