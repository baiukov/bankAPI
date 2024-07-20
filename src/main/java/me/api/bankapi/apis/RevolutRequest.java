package me.api.bankapi.apis;

import me.api.bankapi.enums.SupportedBanks;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RevolutRequest extends IBank {

    private static String keyStorePassword = "291103";

    private final SupportedBanks name = SupportedBanks.REVOLUT;

    public static void main(String[] args) {

        System.out.println(new JSONObject());
        JSONObject token = new JSONObject(getToken("21c31458-0a66-4ac6-8093-f45e2aba7146"));

        JSONObject consent = new JSONObject(getConsent(token.getString("access_token")));
        System.out.println(consent);
        System.out.println(consent.getJSONObject("Data").getString("ConsentId"));
//        System.out.println(getAccessToken("oa_sand_srFaPpioETa5X77afPRIYIT8Gh5oCwhgETffM9WxSI8"));
//        System.out.println(getAccounts("oa_sand_ptpAOOap7QB2-isFVIpLJ4CDiPpdAvp6x5h8UrlgRkg"));
//        System.out.println(getBalance("oa_sand_unka9icLi1RtJEwggN1CAKmF_YqbboJHrOgO6VJlS2E",
//                "03b7dc99-39c8-4d56-b145-af71065ea532"));
    }

    private static String getToken(String clientID) {
        try {
            // Load the client certificate from the resources folder
            String path = "certificates/revolut/transport.pem";
            InputStream certFileStream = RevolutRequest.class.getClassLoader()
                    .getResourceAsStream(path);
            if (certFileStream == null) {
                throw new CertificateException("Transport certificate file not found");
            }

            String certificateFactoryType = "X.509";
            CertificateFactory certificateFactory = CertificateFactory.getInstance(certificateFactoryType);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFileStream);

            // Load the private key from the resources folder
            path = "certificates/revolut/private.key";
            InputStream keyFileStream = RevolutRequest.class.getClassLoader()
                    .getResourceAsStream(path);
            if (keyFileStream == null) {
                throw new CertificateException("Private key file not found");
            }
            byte[] keyBytes = keyFileStream.readAllBytes();
            String privateKeyPEM = new String(keyBytes)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            String keyFactoryAlgorithm = "RSA";
            PrivateKey privateKey = KeyFactory.getInstance(keyFactoryAlgorithm).generatePrivate(keySpec);

            // Initialize the KeyStore with the client certificate and private key
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("certificate", certificate);
            char[] password = new char[0];
            keyStore.setKeyEntry("privateKey",
                    privateKey,
                    password,
                    new java.security.cert.Certificate[]{certificate}
            );

            // Set up KeyManagerFactory to handle the client certificate and private key
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, password);

            // Load the trust store that includes the server's certificate
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            path = "certificates/revolut/truststore.jks";
            try (InputStream trustStoreStream = RevolutRequest.class.getClassLoader()
                    .getResourceAsStream(path)) {
                trustStore.load(trustStoreStream, keyStorePassword.toCharArray()); // Replace with your trust store password
            }

            // Set up TrustManagerFactory with the trust store
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Initialize the SSLContext with KeyManagerFactory and TrustManagerFactory
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            // Prepare the HTTPS connection
            URL url = new URL("https://sandbox-oba-auth.revolut.com/token");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);

            // Construct the request body
//          // 21c31458-0a66-4ac6-8093-f45e2aba7146
            String urlParameters = "grant_type=client_credentials&scope=accounts&client_id=21c31458-0a66-4ac6-8093-f45e2aba7146";
            byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

            // Write the request body to the connection
            try (OutputStream outputStream = connection.getOutputStream()) {
                outputStream.write(postData);
            }

            // Read the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            }

        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getAccessToken(String code) {
        try {
            // Load the client certificate from the resources folder
            InputStream certFileStream = RevolutRequest.class.getClassLoader().getResourceAsStream("certificates/revolut/transport.pem");
            if (certFileStream == null) {
                throw new RuntimeException("Certificate file not found");
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFileStream);

            // Load the private key from the resources folder
            InputStream keyFileStream = RevolutRequest.class.getClassLoader().getResourceAsStream("certificates/revolut/private.key");
            if (keyFileStream == null) {
                throw new RuntimeException("Private key file not found");
            }
            byte[] keyBytes = keyFileStream.readAllBytes();
            String privateKeyPEM = new String(keyBytes).replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            // Initialize the KeyStore with the client certificate and private key
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("certificate", certificate);
            keyStore.setKeyEntry("privateKey", privateKey, new char[0], new java.security.cert.Certificate[]{certificate});

            // Set up KeyManagerFactory to handle the client certificate and private key
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, new char[0]);

            // Load the trust store that includes the server's certificate
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream trustStoreStream = RevolutRequest.class.getClassLoader().getResourceAsStream("certificates/revolut/truststore.jks")) {
                trustStore.load(trustStoreStream, "291103".toCharArray()); // Replace with your trust store password
            }

            // Set up TrustManagerFactory with the trust store
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Initialize the SSLContext with KeyManagerFactory and TrustManagerFactory
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            // Prepare the HTTPS connection
            URL url = new URL("https://sandbox-oba-auth.revolut.com/token");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);

            // Construct the request body
            String urlParameters = "grant_type=authorization_code&code=" + code;
            byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

            // Write the request body to the connection
            try (OutputStream outputStream = connection.getOutputStream()) {
                outputStream.write(postData);
            }

            // Read the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            }

        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }
//
//    public static String getAccounts(String tokenFromS5) {
//        try {
//            // Prepare the HTTPS connection
//            URL url = new URL("https://sandbox-oba.revolut.com/accounts");
//            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
//            connection.setRequestMethod("GET");
//            connection.setRequestProperty("Authorization", "Bearer " + tokenFromS5);
//            connection.setRequestProperty("x-fapi-financial-id", "001580000103UAvAAM");
//
//            // Read the response
//            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
//                String inputLine;
//                StringBuilder response = new StringBuilder();
//                while ((inputLine = in.readLine()) != null) {
//                    response.append(inputLine);
//                }
//                return response.toString();
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        return null;
//    }

    public static String getConsent(String token) {
        try {
            // Load the client certificate from the resources folder
            InputStream certFileStream = RevolutRequest.class.getClassLoader().getResourceAsStream("certificates/revolut/transport.pem");
            if (certFileStream == null) {
                throw new RuntimeException("Certificate file not found");
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFileStream);

            // Load the private key from the resources folder
            InputStream keyFileStream = RevolutRequest.class.getClassLoader().getResourceAsStream("certificates/revolut/private.key");
            if (keyFileStream == null) {
                throw new RuntimeException("Private key file not found");
            }
            byte[] keyBytes = keyFileStream.readAllBytes();
            String privateKeyPEM = new String(keyBytes).replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("certificate", certificate);
            char[] password = new char[0];
            keyStore.setKeyEntry("privateKey",
                    privateKey,
                    password,
                    new java.security.cert.Certificate[]{certificate}
            );

            // Load the trust store that includes the server's certificate
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream trustStoreStream = RevolutRequest.class.getClassLoader().getResourceAsStream("certificates/revolut/truststore.jks")) {
                trustStore.load(trustStoreStream, "291103".toCharArray()); // Replace with your trust store password
            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Initialize the SSLContext with the trust store and the client certificate
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            // Prepare the HTTPS connection
            URL url = new URL("https://sandbox-oba.revolut.com/account-access-consents");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("x-fapi-financial-id", "001580000103UAvAAM");
            connection.setRequestProperty("Authorization", "Bearer " + token);

            // Enable output for writing the request body
            connection.setDoOutput(true);

            // Construct the request JSON body
            String jsonInputString = "{\n" +
                    "    \"Data\": {\n" +
                    "        \"Permissions\": [\n" +
                    "            \"ReadAccountsBasic\",\n" +
                    "            \"ReadAccountsDetail\",\n" +
                    "            \"ReadBalances\"\n" +
                    "        ],\n" +
                    "        \"ExpirationDateTime\": \"2024-12-02T00:00:00+00:00\",\n" +
                    "        \"TransactionFromDateTime\": \"2020-09-03T00:00:00+00:00\",\n" +
                    "        \"TransactionToDateTime\": \"2020-12-03T00:00:00+00:00\"\n" +
                    "    },\n" +
                    "    \"Risk\": {}\n" +
                    "}";

            // Write the request body to the connection
            try (OutputStream outputStream = connection.getOutputStream()) {
                byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                outputStream.write(input, 0, input.length);
            }

            // Read the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            }

        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }
//
//    private static String getBalance(String code, String acc) throws IOException {
//        URL url = new URL("https://oba.revolut.com/accounts/" + acc + "/balances");
//        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
//        connection.setRequestMethod("GET");
//        connection.setRequestProperty("Authorization", "Bearer " + code);
//
//        // Enable output for writing the request body
//        connection.setDoOutput(true);
//
//        // Read the response
//        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
//            String inputLine;
//            StringBuilder response = new StringBuilder();
//            while ((inputLine = in.readLine()) != null) {
//                response.append(inputLine);
//            }
//            return response.toString();
//        }
//    }

}
