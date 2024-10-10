package es.in2.vcverifier.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.config.properties.SecurityProperties;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.model.AuthorizationCodeData;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.security.filters.CustomAuthenticationProvider;
import es.in2.vcverifier.security.filters.CustomAuthorizationRequestConverter;
import es.in2.vcverifier.security.filters.CustomErrorResponseHandler;
import es.in2.vcverifier.security.filters.CustomTokenRequestConverter;
import es.in2.vcverifier.service.ClientAssertionValidationService;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import es.in2.vcverifier.service.VpService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final CryptoComponent cryptoComponent;
    private final DIDService didService;
    private final JWTService jwtService;
    private final ClientAssertionValidationService clientAssertionValidationService;
    private final VpService vpService;
    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final SecurityProperties securityProperties;
    private final RegisteredClientRepository registeredClientRepository;
    private final CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;
    private final ObjectMapper objectMapper;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint ->
                        authorizationServerMetadataEndpoint
                                .authorizationServerMetadataCustomizer(metadata -> {
                                    metadata.claims(claims -> {
                                        claims.put("custom_claim", "custom_value");
                                    });
                        })
                )
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                // Adds an AuthenticationConverter (pre-processor) used when attempting to extract
                                // an OAuth2 authorization request (or consent) from HttpServletRequest to an instance
                                // of OAuth2AuthorizationCodeRequestAuthenticationToken or OAuth2AuthorizationConsentAuthenticationToken.
                                .authorizationRequestConverter(new CustomAuthorizationRequestConverter(didService,jwtService,cryptoComponent,cacheStoreForAuthorizationRequestJWT,cacheStoreForOAuth2AuthorizationRequest,securityProperties))
                                .errorResponseHandler(new CustomErrorResponseHandler())

                )
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(new CustomTokenRequestConverter(jwtService, clientAssertionValidationService, vpService, cacheStoreForAuthorizationCodeData,oAuth2AuthorizationService(),objectMapper))
                                .authenticationProvider(new CustomAuthenticationProvider(cryptoComponent,jwtService,registeredClientRepository,securityProperties,objectMapper))
                )
                .oidc(Customizer.withDefaults());
        // Enable OpenID Connect 1.0

        return http.build();
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(cryptoComponent.getECKey());
        return ( jwkSelector, context ) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<>(
                "aud", securityProperties.authorizationServer()::equals);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(audienceValidator);
        jwtDecoder.setJwtValidator(withAudience);
        return jwtDecoder;
    }
    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }


//    @Bean
//    public OidcProviderConfiguration oidcProviderConfiguration() {
//        // Create a map to hold your claims
//        Map<String, Object> claims = new HashMap<>();
//
////        // Add default claims
////        claims.put("issuer", securityProperties.authorizationServer());
////        claims.put("authorization_endpoint", securityProperties.authorizationServer() + "/oidc/authorize");
////        claims.put("device_authorization_endpoint", securityProperties.authorizationServer() + "/oidc/device_authorization");
////        claims.put("token_endpoint", securityProperties.authorizationServer() + "/oidc/token");
////        claims.put("token_endpoint_auth_methods_supported", new String[] {"client_secret_basic", "client_secret_post","client_secret_jwt","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"});
////        claims.put("jwks_uri", securityProperties.authorizationServer() + "/oidc/jwks");
////        claims.put("userinfo_endpoint", securityProperties.authorizationServer() + "/oidc/userinfo");
////        claims.put("end_session_endpoint", securityProperties.authorizationServer() + "/oidc/logout");
////        claims.put("response_types_supported", new String[] {"code"});
////        claims.put("grant_types_supported", new String[] {"authorization_code","client_credentials","refresh_token","urn:ietf:params:oauth:grant-type:device_code","urn:ietf:params:oauth:grant-type:token-exchange"});
////        claims.put("revocation_endpoint", securityProperties.authorizationServer() + "/oidc/revoke");
////        claims.put("revocation_endpoint_auth_methods_supported", new String[] {"client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"});
////        claims.put("introspection_endpoint", securityProperties.authorizationServer() + "/oidc/introspect");
////        claims.put("introspection_endpoint_auth_methods_supported", new String[] {"client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","tls_client_auth","self_signed_tls_client_auth"});
////        claims.put("code_challenge_methods_supported", new String[] {"S256"});
////        claims.put("tls_client_certificate_bound_access_tokens", true);
//
//        // Add custom claim
//        claims.put("request_uri_parameter_supported", "true"); // Add your custom property
//
//        // Build the OidcProviderConfiguration with the claims
//        return OidcProviderConfiguration.withClaims(claims)
//                .subjectTypes(subjectTypes -> subjectTypes.add("public")) // Add subject types if needed
//                .idTokenSigningAlgorithm("RS256") // Set signing algorithm if needed
//                .issuer(securityProperties.authorizationServer())
//                .authorizationEndpoint(securityProperties.authorizationServer() + "/oidc/authorize")
//                .deviceAuthorizationEndpoint(securityProperties.authorizationServer() + "/oidc/device_authorization")
//                .tokenEndpoint(securityProperties.authorizationServer() + "/oidc/token")
//                .tokenIntrospectionEndpoint(securityProperties.authorizationServer() + "/oidc/introspect")
//                .tokenRevocationEndpoint(securityProperties.authorizationServer() + "/oidc/revoke")
//                .jwkSetUrl(securityProperties.authorizationServer() + "/oidc/jwks")
//                .endSessionEndpoint(securityProperties.authorizationServer() + "/oidc/logout")
//                .userInfoEndpoint(securityProperties.authorizationServer() + "/oidc/userinfo")
//                .clientRegistrationEndpoint(securityProperties.authorizationServer() + "/oidc/register")
//                .responseTypes(responseTypes -> responseTypes.add("code"))
//                .build();
//    }

    //Customiza los endpoint del Authorization Server
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(securityProperties.authorizationServer())
                .authorizationEndpoint("/oidc/authorize")
                .deviceAuthorizationEndpoint("/oidc/device_authorization")
                .deviceVerificationEndpoint("/oidc/device_verification")
                .tokenEndpoint("/oidc/token")
                .tokenIntrospectionEndpoint("/oidc/introspect")
                .tokenRevocationEndpoint("/oidc/revoke")
                .jwkSetEndpoint("/oidc/jwks")
                .oidcLogoutEndpoint("/oidc/logout")
                .oidcUserInfoEndpoint("/oidc/userinfo")
                .oidcClientRegistrationEndpoint("/oidc/register")
                .setting("test","test")
                .build();
    }

}
