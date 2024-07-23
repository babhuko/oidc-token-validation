import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class JwtValidator {

    public static void main(String[] args) {
        String token = "your_jwt_token";  // Replace with your JWT token
        String jwksUrl = "https://{yourOktaDomain}/oauth2/default/v1/keys";  // Replace with your Okta JWKS URL
        String issuer = "https://{yourOktaDomain}/oauth2/default";  // Replace with your Okta issuer
        String audience = "api://default";  // Replace with your audience

        try {
            // Fetch the public keys from Okta
            JWKSet jwkSet = JWKSet.load(new URL(jwksUrl));
            SignedJWT signedJWT = SignedJWT.parse(token);
            String keyId = signedJWT.getHeader().getKeyID();

            // Find the public key that matches the key ID in the token
            JWK jwk = jwkSet.getKeyByKeyId(keyId);
            if (jwk == null) {
                throw new IllegalArgumentException("No matching key found in JWKS");
            }

            // Verify the token's signature
            JWSVerifier verifier = new RSASSAVerifier((RSAKey) jwk.toRSAKey());
            if (!signedJWT.verify(verifier)) {
                throw new IllegalArgumentException("Invalid token signature");
            }

            // Validate the token claims (e.g., issuer, audience)
            Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();
            if (!issuer.equals(claims.get("iss"))) {
                throw new IllegalArgumentException("Invalid token issuer");
            }
            if (!audience.equals(claims.get("aud"))) {
                throw new IllegalArgumentException("Invalid token audience");
            }

            System.out.println("Token is valid");
            System.out.println("Claims: " + new ObjectMapper().writeValueAsString(claims));

        } catch (Exception e) {
            System.out.println("Invalid token: " + e.getMessage());
        }
    }
}
