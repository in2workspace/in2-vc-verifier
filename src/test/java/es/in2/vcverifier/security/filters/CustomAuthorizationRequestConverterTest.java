package es.in2.vcverifier.security.filters;

import es.in2.vcverifier.config.CacheStore;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.model.AuthorizationRequestJWT;
import es.in2.vcverifier.service.DIDService;
import es.in2.vcverifier.service.JWTService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.util.UUID;

import static es.in2.vcverifier.util.Constants.REQUEST_URI;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomAuthorizationRequestConverterTest {

    @Mock
    private DIDService didService;

    @Mock
    private JWTService jwtService;

    @Mock
    private CryptoComponent cryptoComponent;

    @Mock
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    @Mock
    private HttpResponse<String> httpResponse;
    @Mock
    private HttpClient httpClient;


    @InjectMocks
    private CustomAuthorizationRequestConverter converter;

    @Test
    void convert_WhenRequestUriIsProvided_ShouldRetrieveAndVerifyJwt() throws Exception {
        // Setup
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(REQUEST_URI)).thenReturn("https://example.com/jwt/1234");
        when(mockRequest.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(mockRequest.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("openid learcredential");
        when(mockRequest.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("did:key:zDnaeUcW7pAV2xfcEMRsi3tsgYSYkLEf8mbSCZ7YFhKDu6XcR");
        when(mockRequest.getParameter(OAuth2ParameterNames.STATE)).thenReturn("state");

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVVY1c3cEFWMnhmY0VNUnNpM3RzZ1lTWWtMRWY4bWJTQ1o3WUZoS0R1NlhjUiJ9.eyJzY29wZSI6Im9wZW5pZF9sZWFyY3JlZGVudGlhbCIsImlzcyI6ImRpZDprZXk6ekRuYWVVY1c3cEFWMnhmY0VNUnNpM3RzZ1lTWWtMRWY4bWJTQ1o3WUZoS0R1NlhjUiIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL2NiIiwiZXhwIjoxNzU4MTkzNjEyLCJpYXQiOjE3MjcwODk2MTIsImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVVY1c3cEFWMnhmY0VNUnNpM3RzZ1lTWWtMRWY4bWJTQ1o3WUZoS0R1NlhjUiJ9.9QoanrjKyIOLQpQ3rj2ucUzwJa6XH1T5-pabnAjYmJmyl5lNSG1v0y5vEvTLlYugrrwUjxnv9tsbqXfirz6kMQ";
        when(httpResponse.body()).thenReturn(jwt);
        when(httpClient.send(any(HttpRequest.class), eq(HttpResponse.BodyHandlers.ofString()))).thenReturn(httpResponse);


        PublicKey publicKey = mock(PublicKey.class);
        when(didService.getPublicKeyFromDid(anyString())).thenReturn(publicKey);
        doNothing().when(jwtService).verifyJWTSignature(anyString(), any(PublicKey.class), any());

        String nonce = UUID.randomUUID().toString();
        String authRequest = "authRequest";

        when(jwtService.generateJWT(anyString())).thenReturn(authRequest);
//        when(securityProperties.authorizationServer()).thenReturn("https://auth.server");

        // Action
        Exception exception = assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () ->
                converter.convert(mockRequest));

    }

}

