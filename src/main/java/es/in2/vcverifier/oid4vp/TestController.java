package es.in2.vcverifier.oid4vp;

import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.crypto.CryptoComponent;
import es.in2.vcverifier.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final CryptoComponent cryptoComponent;
    private final JWTService jwtService;
    @GetMapping("/generate-auth")
    public String generateJWTAuthRequest() {
        String did = cryptoComponent.getECKey().getKeyID();

        Instant issueTime = Instant.now();
        Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(did)
                .issueTime(java.util.Date.from(issueTime))
                .expirationTime(java.util.Date.from(expirationTime))
                .claim("client_id", did)
                .claim("redirect_uri", "https://example.com")
                .claim("scope", "openid learcredential")
                .claim("response_type", "code")
                .build();

        return jwtService.generateJWT(payload.toString());
    }
}
