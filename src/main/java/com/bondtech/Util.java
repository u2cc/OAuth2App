package com.bondtech;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class Util {
    private static final String CLIENT_ID = "client-id";
    private static final String TOKEN_ENDPOINT = "http://localhost:8282/oauth2/token"; // Update as needed
    private static final String KEYSTORE_PATH = System.getenv("keystore_path"); // Path to your JKS file
    private static final String KEYSTORE_PASSWORD = System.getenv("keystore_password"); // Keystore password
    private static final String ALIAS = System.getenv("key_alias"); // Alias of the private key
    private static final String KEY_PASSWORD = System.getenv("key_password"); // Update as needed

    public static String generateClientAssertion() throws Exception {
        // Load private key from file
        RSAPrivateKey privateKey = loadPrivateKeyFromJKS(KEYSTORE_PATH, KEYSTORE_PASSWORD, ALIAS, KEY_PASSWORD);

        // Create JWT claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(CLIENT_ID)  // "iss": client_id
                .subject(CLIENT_ID) // "sub": client_id
                .audience(TOKEN_ENDPOINT) // "aud": token endpoint
                .issueTime(new Date()) // "iat": now
                .expirationTime(new Date(System.currentTimeMillis() + 3000000)) // "exp": 50 mins from now
                .jwtID(UUID.randomUUID().toString()) // "jti": unique ID
                .build();

        // Create JWS header with RSA256
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID("bondtech.com")
                .type(JOSEObjectType.JWT)// Use the same "kid" as in JWK Set
                .build();

        // Sign JWT
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(privateKey));

        return signedJWT.serialize(); // Return as a string
    }

    private static RSAPrivateKey loadPrivateKeyFromJKS(String keystorePath, String keystorePassword, String alias, String keyPassword) throws Exception {
        // Load keystore from file
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream keystoreStream = new FileInputStream(keystorePath)) {
            keyStore.load(keystoreStream, keystorePassword.toCharArray());
        }

        // Retrieve the private key from the keystore
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());

        if (privateKey instanceof RSAPrivateKey) {
            return (RSAPrivateKey) privateKey;
        } else {
            throw new Exception("Private key is not of type RSAPrivateKey");
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Client Assertion: " + generateClientAssertion());
    }
}
