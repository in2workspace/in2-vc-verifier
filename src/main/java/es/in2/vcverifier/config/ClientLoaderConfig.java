package es.in2.vcverifier.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.model.ClientData;
import es.in2.vcverifier.service.TrustFrameworkService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class ClientLoaderConfig {

    private final ObjectMapper objectMapper;
    private final TrustFrameworkService trustFrameworkService;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> clients = loadClients(); // Cargar los clientes
        return new InMemoryRegisteredClientRepository(clients); // Pasar los clientes al repositorio
    }

    private List<RegisteredClient> loadClients() {
        try {
            // Leer el archivo JSON
            String clientsJson = trustFrameworkService.fetchAllowedClient();
            List<ClientData> clientsData = objectMapper.readValue(clientsJson, new TypeReference<>() {
            });

            List<RegisteredClient> registeredClients = new ArrayList<>();

            // Convertir cada ClientData a RegisteredClient y agregarlo a la lista
            for (ClientData clientData : clientsData) {
                RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(clientData.clientId())
                        .clientAuthenticationMethods(authMethods -> clientData.clientAuthenticationMethods().forEach(method ->
                                authMethods.add(new ClientAuthenticationMethod(method))))
                        .authorizationGrantTypes(grantTypes -> clientData.authorizationGrantTypes().forEach(grantType ->
                                grantTypes.add(new AuthorizationGrantType(grantType))))
                        .redirectUris(uris -> uris.addAll(clientData.redirectUris()))
                        .postLogoutRedirectUris(uris -> uris.addAll(clientData.postLogoutRedirectUris()))
                        .scopes(scopes -> scopes.addAll(clientData.scopes()));

                if (clientData.clientSecret() != null && !clientData.clientSecret().isBlank()) {
                    registeredClientBuilder.clientSecret(clientData.clientSecret());
                }
                // Configurar ClientSettings
                ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                        .requireAuthorizationConsent(clientData.requireAuthorizationConsent());

                // Configurar valores opcionales si están presentes en el JSON
                if (clientData.jwkSetUrl() != null) {
                    clientSettingsBuilder.jwkSetUrl(clientData.jwkSetUrl());
                }

                if (clientData.tokenEndpointAuthenticationSigningAlgorithm() != null) {
                    clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(
                            SignatureAlgorithm.from(clientData.tokenEndpointAuthenticationSigningAlgorithm()));
                }

                if (clientData.requireProofKey() != null) {
                    clientSettingsBuilder.requireProofKey(clientData.requireProofKey());
                }


                registeredClientBuilder.clientSettings(clientSettingsBuilder.build());

                registeredClients.add(registeredClientBuilder.build());
            }
            return registeredClients;
        } catch (Exception e) {
            throw new RuntimeException("Error loading clients from JSON", e);
        }
    }
}


