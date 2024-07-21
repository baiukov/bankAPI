package me.api.bankapi.apis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.common.util.StringUtils;
import me.api.bankapi.enums.revolut.RevolutPermissions;
import me.api.bankapi.exeptions.MalformedBuilder;
import me.api.bankapi.mapper.RevolutRowMapper;
import me.api.bankapi.model.revolut.RevolutAccount;
import me.api.bankapi.model.revolut.RevolutBalance;
import me.api.bankapi.model.revolut.RevolutBeneficiary;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * An API class which is designed for work with Revolut API.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public class RevolutAPI {

    /**
     * Row mapper for mapping objects from JSON raw objects
     */
    private final RevolutRowMapper rowMapper = new RevolutRowMapper();
    private X509Certificate transportCertificate;
    private PrivateKey privateKey;
    private TrustManagerFactory trustManagerFactory;
    private final boolean isSandbox;
    private String clientID;
    private SSLContext sslContext;
    private String kid;
    private String consentExpiration;
    private String transactionFrom;
    private String transactionTo;
    private final List<RevolutPermissions> consentPermissions = new ArrayList<>();

    private final String sandboxTokenURL = "https://sandbox-oba-auth.revolut.com/token";
    private final String sandboxUserConsentURL = "https://sandbox-oba.revolut.com/ui/index.html?response_type=code%%20id_token&scope=accounts&redirect_uri=%s&client_id=%s&request=%s&state=example_state";
    private final String sandboxURL = "https://sandbox-oba.revolut.com/";
    private final String prodTokenURL = "https://oba-auth.revolut.com/token";
    private final String prodUserConsentURL = "https://oba.revolut.com/ui/index.html?response_type=code%20id_token&scope=accounts&redirect_uri=%s&client_id=%s&request=%s&state=example_state";
    private final String prodURL = "https://oba.revolut.com/";

    private String accessToken;

    private RevolutAPI(RevolutAPIBuilder builder)
            throws MalformedBuilder, CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, KeyStoreException, UnrecoverableKeyException, KeyManagementException
    {
        // set whether this api dedicated for sandbox
        this.isSandbox = builder.isSandbox;

        // if there is an access token, it can be enough for getting data, if not we need more properties to get it
        if (builder.accessToken != null) {
            this.accessToken = builder.accessToken;
            return;
        }

        // transport certificate instance, path or file
        if (builder.transportCertificatePath == null &&
            builder.transportCertificate == null &&
            builder.transportCertificateFile == null
        ) {
            throw new MalformedBuilder("No certificate, certificate path nor certificate file provided");
        } else if (builder.transportCertificate != null) {
            this.transportCertificate = builder.transportCertificate;
        } else if (builder.transportCertificateFile != null) {
            this.transportCertificate = getCertificate(builder.transportCertificateFile);
        } else {
            this.transportCertificate = getCertificate(getFile(builder.transportCertificatePath));
        }

        // private key instance, path or file
        if (builder.privateKey == null &&
            builder.privateKeyPath == null &&
            builder.privateKeyFile == null
        ) {
            throw new MalformedBuilder("No private key, private key path nor private key file provided");
        } else if (builder.privateKey != null) {
            this.privateKey = builder.privateKey;
        } else if (builder.privateKeyFile != null) {
            this.privateKey = getPrivateKey(builder.privateKeyFile);
        } else {
            this.privateKey = getPrivateKey(getFile(builder.privateKeyPath));
        }

        // trust manager factory instance, path to trust store or file of trus store certificate
        if (builder.trustManagerFactory == null &&
            builder.trustStoreFile == null &&
            builder.trustStorePath == null
        ) {
            throw new MalformedBuilder("No trust manager factory, trust store path nor trust store file provided");
        } else if (builder.trustManagerFactory != null) {
            this.trustManagerFactory = builder.trustManagerFactory;
        } else if (builder.trustStoreFile != null) {
            this.trustManagerFactory = getTrustManagerFactory(builder.trustStoreFile, "");
        } else {
            this.trustManagerFactory = getTrustManagerFactory(getFile(builder.trustStorePath), "291103");
        }

        // ssl context based on certificates
        this.sslContext = builder.sslContext == null ? getSSLContext() : builder.sslContext;

        this.clientID = builder.clientID;

        // permissions required for consent
        if (!builder.consentPermission.isEmpty()) {
            for (RevolutPermissions permission : builder.consentPermission) {
                RevolutPermissions dependency = permission.dependency();
                if (dependency != null && !builder.consentPermission.contains(dependency)) {
                    throw new MalformedBuilder(String.format("Provided permission %s requires permission %s",
                            permission, dependency));
                }
                this.consentPermissions.add(permission);
            }
        }

        if (builder.kid == null) {
            throw new MalformedBuilder("No kid provided.");
        }
        this.kid = builder.kid;

        ZoneId systemZone = ZoneId.systemDefault();
        if (builder.consentExpirationString != null) {
            this.consentExpiration = builder.consentExpirationString;
        } else if (builder.consentExpirationTimestamp != null) {
            this.consentExpiration = builder.consentExpirationTimestamp.atZone(systemZone)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        } else if (builder.consentExpiration != null) {
            this.consentExpiration = builder.consentExpiration.atZone(systemZone)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        }

        if (builder.transactionFromString != null) {
            this.transactionFrom = builder.transactionFromString;
        } else if (builder.transactionFromTimestamp != null) {
            this.transactionFrom = builder.transactionFromTimestamp.atZone(systemZone)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        } else if (builder.transactionFrom != null) {
            this.transactionFrom = builder.transactionFrom.atZone(systemZone)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        }

        if (builder.transactionToString != null) {
            this.transactionTo = builder.transactionToString;
        } else if (builder.transactionToTimestamp != null) {
            this.transactionTo = builder.transactionToTimestamp.atZone(systemZone)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        } else if (builder.transactionTo != null) {
            this.transactionTo = builder.transactionTo.atZone(systemZone)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        }
    }

    public static class RevolutAPIBuilder {

        private X509Certificate transportCertificate;
        private InputStream transportCertificateFile;
        private String transportCertificatePath;

        private PrivateKey privateKey;
        private InputStream privateKeyFile;
        private String privateKeyPath;

        private TrustManagerFactory trustManagerFactory;
        private InputStream trustStoreFile;
        private String trustStorePath;

        private SSLContext sslContext;

        private boolean isSandbox;
        private String clientID;

        private String kid;

        private List<RevolutPermissions> consentPermission = new ArrayList<>();

        private LocalDateTime consentExpiration;
        private String consentExpirationString;
        private Instant consentExpirationTimestamp;

        private LocalDateTime transactionFrom;
        private String transactionFromString;
        private Instant transactionFromTimestamp;

        private LocalDateTime transactionTo;
        private String transactionToString;
        private Instant transactionToTimestamp;

        private String accessToken;

        /**
         * An instance of transport certificate
         *
         * @param transportCertificate certificate
         * @return builder
         */
        public RevolutAPIBuilder setTransportCertificate(X509Certificate transportCertificate) {
            this.transportCertificate = transportCertificate;
            return this;
        }

        /**
         * An instance of transport certificate's file as an input stream
         *
         * @param transportCertificateFile file
         * @return builder
         */
        public RevolutAPIBuilder setTransportCertificateFile(InputStream transportCertificateFile) {
            this.transportCertificateFile = transportCertificateFile;
            return this;
        }

        /**
         * A path to the transport certificate's file
         *
         * @param transportCertificatePath path
         * @return builder
         */
        public RevolutAPIBuilder setTransportCertificatePath(String transportCertificatePath) {
            this.transportCertificatePath = transportCertificatePath;
            return this;
        }

        /**
         * An instance of private key
         *
         * @param privateKey private key
         * @return builder
         */
        public RevolutAPIBuilder setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        /**
         * An instance of private key's file as an input stream
         *
         * @param privateKeyFile file
         * @return builder
         */
        public RevolutAPIBuilder setPrivateKeyFile(InputStream privateKeyFile) {
            this.privateKeyFile = privateKeyFile;
            return this;
        }

        /**
         * A path to the private key's file
         *
         * @param privateKeyPath path
         * @return builder
         */
        public RevolutAPIBuilder setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
            return this;
        }

        /**
         * An instance of trust manager factory
         *
         * @param trustManagerFactory trust manager factory
         * @return builder
         */
        public RevolutAPIBuilder setTrustManagerFactory(TrustManagerFactory trustManagerFactory) {
            this.trustManagerFactory = trustManagerFactory;
            return this;
        }

        /**
         * An instance of trust store's file as an input stream
         *
         * @param trustStoreFile file
         * @return builder
         */
        public RevolutAPIBuilder setTrustStoreFile(InputStream trustStoreFile) {
            this.trustStoreFile = trustStoreFile;
            return this;
        }

        /**
         * A path to the trust store's file
         *
         * @param trustStorePath path
         * @return builder
         */
        public RevolutAPIBuilder setTrustStorePath(String trustStorePath) {
            this.trustStorePath = trustStorePath;
            return this;
        }

        /**
         * Whether the instance of Revolut API dedicated to the sandbox or production
         *
         * @param isSandbox isSandbox
         * @return builder
         */
        public RevolutAPIBuilder setIsSandbox(boolean isSandbox) {
            this.isSandbox = isSandbox;
            return this;
        }

        /**
         * Client identification from application
         *
         * @param clientID id
         * @return builder
         */
        public RevolutAPIBuilder setClientID(String clientID) {
            this.clientID = clientID;
            return this;
        }

        /**
         * SSL context or certificates should be provided
         *
         * @param sslContext context
         * @return builder
         */
        public RevolutAPIBuilder setSSLContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * Expiration of the consent with user, if set to null it will have open date.
         *
         * @param consentExpiration date
         * @return builder
         */
        public RevolutAPIBuilder setConsentExpiration(LocalDateTime consentExpiration) {
            this.consentExpiration = consentExpiration;
            return this;
        }

        /**
         * Expiration of the consent with user as a string, if set to null it will have open date.
         *
         * @param consentExpirationString date
         * @return builder
         */
        public RevolutAPIBuilder setConsentExpirationString(String consentExpirationString) {
            this.consentExpirationString = consentExpirationString;
            return this;
        }

        /**
         * Expiration of the consent with user as an instant, if set to null it will have open date.
         *
         * @param consentExpirationTimestamp date
         * @return builder
         */
        public RevolutAPIBuilder setConsentExpirationTimestamp(Instant consentExpirationTimestamp) {
            this.consentExpirationTimestamp = consentExpirationTimestamp;
            return this;
        }

        /**
         * Transaction to date to be selected, if set to null it will have date open date
         *
         * @param transactionTo date
         * @return builder
         */
        public RevolutAPIBuilder setTransactionToDate(LocalDateTime transactionTo) {
            this.transactionTo = transactionTo;
            return this;
        }

        /**
         * Transaction to date to be selected as a string, if set to null it will have open date
         *
         * @param transactionToString date
         * @return builder
         */
        public RevolutAPIBuilder setTransactionToDateString(String transactionToString) {
            this.transactionToString = transactionToString;
            return this;
        }

        /**
         * Transaction to date to be selected as an instant, if set to null it will have open date
         *
         * @param transactionToTimestamp date
         * @return builder
         */
        public RevolutAPIBuilder setTransactionToDateTimestamp(Instant transactionToTimestamp) {
            this.transactionToTimestamp = transactionToTimestamp;
            return this;
        }

        /**
         * Transaction from date to be selected, if set to null it will have date of user registration.
         *
         * @param transactionFrom date
         * @return builder
         */
        public RevolutAPIBuilder setTransactionFromDate(LocalDateTime transactionFrom) {
            this.transactionFrom = transactionFrom;
            return this;
        }

        /**
         * Transaction from date to be selected as a string, if set to null it will have date of user registration.
         *
         * @param transactionFromString date
         * @return builder
         */
        public RevolutAPIBuilder setTransactionFromDateString(String transactionFromString) {
            this.transactionFromString = transactionFromString;
            return this;
        }

        /**
         * Transaction from date to be selected as an instant, if set to null it will have date of user registration.
         *
         * @param transactionFromTimestamp date
         * @return builder
         */
        public RevolutAPIBuilder setTransactionFromTimestamp(Instant transactionFromTimestamp) {
            this.transactionFromTimestamp = transactionFromTimestamp;
            return this;
        }

        /**
         * Permissions to be asked from user on consent signing
         *
         * @param permissions ...
         * @return builder
         */
        public RevolutAPIBuilder setPermissions(RevolutPermissions ... permissions) {
            this.consentPermission = List.of(permissions);
            return this;
        }

        /**
         * Kid value from your specific application and consent request.
         *
         * @param kid kid
         * @return builder
         */
        public RevolutAPIBuilder setKid(String kid) {
            this.kid = kid;
            return this;
        }

        /**
         * If there is an available access token api will work for requests immediately
         *
         * @param accessToken token
         * @return builder
         */
        public RevolutAPIBuilder setAccessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public RevolutAPIBuilder() { }

        public RevolutAPI build()
                throws MalformedBuilder, CertificateException, IOException, NoSuchAlgorithmException,
                InvalidKeySpecException, KeyStoreException, UnrecoverableKeyException, KeyManagementException
        {
            return new RevolutAPI(this);
        }

    }

    private X509Certificate getCertificate(InputStream file) throws CertificateException {
        String certificateFactoryType = "X.509";
        CertificateFactory certificateFactory = CertificateFactory.getInstance(certificateFactoryType);
        return (X509Certificate) certificateFactory.generateCertificate(file);
    }

    /**
     * Method for finding a file by path
     *
     * @param path - path to the file
     * @return InputStream instance
     * @throws CertificateException if file is not found
     */
    private InputStream getFile(String path) throws CertificateException {
        InputStream fileStream = RevolutRequest.class.getClassLoader().getResourceAsStream(path);
        if (fileStream == null) {
            throw new CertificateException("Transport certificate file not found");
        }
        return fileStream;
    }

    /**
     * Method for generating a private key from file.
     *
     * @param keyFileStream file
     * @return private key
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private PrivateKey getPrivateKey(InputStream keyFileStream)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] keyBytes = keyFileStream.readAllBytes();
        String privateKeyPEM = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        String keyFactoryAlgorithm = "RSA";
        return KeyFactory.getInstance(keyFactoryAlgorithm).generatePrivate(keySpec);
    }

    /**
     * Method for generating a trust manager factory from trust store file provided.
     *
     * @param trustStoreFile file
     * @param keyStorePassword password from key storage
     * @return trust manager factory
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private TrustManagerFactory getTrustManagerFactory(InputStream trustStoreFile, String keyStorePassword)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException
    {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(trustStoreFile, keyStorePassword.toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return trustManagerFactory;
    }

    /**
     * Method for generating a ssl context from the private key provided
     *
     * @return sslCotext
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws KeyManagementException
     */
    private SSLContext getSSLContext()
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyManagementException
    {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("certificate", transportCertificate);
        char[] password = new char[0];
        keyStore.setKeyEntry("privateKey",
                privateKey,
                password,
                new java.security.cert.Certificate[] { transportCertificate }
        );
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    /**
     * Method for retrieving a token with authorization by certificates and provided client ID
     *
     * @return token
     * @throws IOException exception happened during connecting
     */
    public String getToken() throws IOException {
        URL url = new URL(isSandbox ? sandboxTokenURL : prodTokenURL);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setDoOutput(true);

        String urlParameters = "grant_type=client_credentials&scope=accounts&client_id=" + clientID;
        byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(postData);
        }
        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            return response.toString();
        }
    }

    /**
     * Method for receiving a consent by using provided raw token object.
     *
     * @param token json object of token
     * @return raw json object of consent
     * @throws IOException - problem during connecting
     */
    public String getConsent(JSONObject token) throws IOException {
        return getConsent(token.getString("access_token"));
    }

    /**
     * Method for receiving a consent by using provided token directly.
     *
     * @param token token as a string
     * @return raw json object of consent
     * @throws IOException - problem during connecting
     */
    public String getConsent(String token) throws IOException {
        URL url = new URL(String.format("%s%s", isSandbox ? sandboxURL : prodURL, "account-access-consents"));
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("x-fapi-financial-id", "001580000103UAvAAM");
        connection.setRequestProperty("Authorization", "Bearer " + token);

        connection.setDoOutput(true);

        JSONObject data = new JSONObject();
        data.put("Permissions", new JSONArray(consentPermissions.stream().map(RevolutPermissions::value).toList()));
        if (!StringUtils.isBlank(consentExpiration)) data.put("ExpirationDateTime", consentExpiration);
        if (!StringUtils.isBlank(transactionFrom)) data.put("TransactionFromDateTime", transactionFrom);
        if (!StringUtils.isBlank(transactionTo)) data.put("TransactionToDateTime", transactionTo);

        JSONObject request = new JSONObject();
        request.put("Data", data);
        request.put("Risk", new JSONObject());

        try (OutputStream outputStream = connection.getOutputStream()) {
            byte[] input = request.toString().getBytes(StandardCharsets.UTF_8);
            outputStream.write(input, 0, input.length);
        }

        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            return response.toString();
        }
    }

    /**
     * Method for receiving a consent by using provided properties only.
     * Firstly it gets a token by certificates and client id.
     *
     * @return raw json object of consent
     * @throws IOException - problem during connecting
     */
    public String getConsent() throws IOException {
        JSONObject token = new JSONObject(getToken());
        return getConsent(token.getString("access_token"));
    }

    /**
     * Method for receiving an access token after signing a consent with user.
     *
     * @param code code provided after user signing
     * @return raw json object access token
     * @throws IOException - problem during connecting
     */
    public String getAccessToken(String code) throws IOException {
        URL url = new URL(isSandbox ? sandboxTokenURL : prodTokenURL);
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
    }

    /**
     * Method for receiving a jwt parameters for redirecting a user to the auth page.
     * Firstly it generates a token and consent from certificates and client id provided
     *
     * @param redirectURL url, where user will be redirected after signing
     * @return raw jwt parameters
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public String getJWTParameters(String redirectURL)
            throws IOException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException,
            InvalidKeyException
    {
        JSONObject consent = new JSONObject(getConsent());
        JSONObject data = consent.getJSONObject("Data");
        if (data == null) return null;
        String consentId = data.getString("ConsentId");
        return getJWTParameters(redirectURL, consentId);
    }

    /**
     * Method for receiving a jwt parameters directly from consent id for redirecting a user to the auth page.
     *
     * @param redirectURL url, where user will be redirected after signing
     * @param consentID consent id
     * @return raw jwt parameters
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public String getJWTParameters(String redirectURL, String consentID)
            throws JsonProcessingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            SignatureException
    {
        Map<String, Object> jwtHeader = new HashMap<>();
        jwtHeader.put("alg", "PS256");
        jwtHeader.put("kid", kid);
        jwtHeader.put("typ", "JWT");

        Map<String, Object> payload = new HashMap<>();
        payload.put("response_type", "code id_token");
        payload.put("client_id", clientID);
        payload.put("redirect_uri", redirectURL);
        payload.put("scope", "accounts");
        payload.put("claims", new HashMap<String, Object>() {{
            put("id_token", new HashMap<String, Object>() {{
                put("openbanking_intent_id", new HashMap<String, Object>() {{
                    put("value", consentID);
                }});
            }});
        }});

        String header = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(new ObjectMapper().writeValueAsBytes(jwtHeader));
        String body = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(new ObjectMapper().writeValueAsBytes(payload));
        String message = String.format("%s.%s", header, body);

        Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        String signatureString = Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());

        return String.format("%s.%s.%s", header, body, signatureString);
    }

    /**
     * Method for receiving an url with auth page for user using JWT parameters
     *
     * @param redirectURL url, where user will be redirected after signing
     * @return url with auth page
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public String getConsentURL(String redirectURL)
            throws IOException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException
    {
        return String.format(
                isSandbox ? sandboxUserConsentURL : prodUserConsentURL,
                redirectURL,
                clientID,
                getJWTParameters(redirectURL)
        );
    }

    /**
     * Method for receiving an url with auth page for user using JWT parameters and directly specified consent id
     *
     * @param redirectURL url, where user will be redirected after signing
     * @param consentId consent id
     * @return url with auth page
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public String getConsentURL(String redirectURL, String consentId)
            throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException,
            JsonProcessingException
    {
        return String.format(
                isSandbox ? sandboxUserConsentURL : prodUserConsentURL,
                redirectURL,
                clientID,
                getJWTParameters(redirectURL, consentId)
        );
    }

    /**
     * Retrieve all accounts raw.
     *
     * @return raw json object with all accounts
     * @throws IOException
     */
    public String getAccountsRaw() throws IOException {
        return sendRequest((isSandbox ? sandboxURL : prodURL) + "accounts");
    }

    /**
     * Retrieve all accounts.
     *
     * @return all accounts mapped
     * @throws IOException
     */
    public List<RevolutAccount> getAccounts() throws IOException {
        return rowMapper.getAccounts(rowMapper.parse(getAccountsRaw()));
    }

    /**
     * Get the information about a specific account by ID raw.
     *
     * @param accountID id
     * @return raw json object with account
     * @throws IOException
     */
    public String getAccountRaw(String accountID) throws IOException {
        return sendRequest(String.format("%s/accounts/%s", isSandbox ? sandboxURL : prodURL, accountID))        ;
    }

    /**
     * Get the information about a specific account by ID.
     *
     * @param accountID id
     * @return account object mapped
     * @throws IOException
     */
    public RevolutAccount getAccount(String accountID) throws IOException {
        return rowMapper.getAccounts(rowMapper.parse(getAccountRaw(accountID))).stream().findFirst().orElse(null);
    }

    /**
     * Retrieve an account balance raw
     *
     * @param accountID id
     * @return raw json object with account balance
     * @throws IOException
     */
    public String getBalanceRaw(String accountID) throws IOException {
        return sendRequest(String.format("%saccounts/%s/balances", isSandbox ? sandboxURL : prodURL, accountID));
    }

    /**
     * Retrieve an account balance
     *
     * @param accountID id
     * @return account balance mapped
     * @throws IOException
     */
    public RevolutBalance getBalance(String accountID) throws IOException {
        return rowMapper.getBalance(rowMapper.parse(getBalanceRaw(accountID)));
    }

    /**
     * Retrieve all account's beneficiaries raw
     *
     * @param accountID id
     * @return raw json object with beneficiaries
     * @throws IOException
     */
    public String getBeneficiariesRaw(String accountID) throws IOException {
        return sendRequest(String.format("%saccounts/%s/beneficiaries", isSandbox ? sandboxURL : prodURL, accountID));
    }

    /**
     * Retrieve all account's beneficiaries.
     *
     * @param accountID id
     * @return beneficiaries object mapped
     * @throws IOException
     */
    public List<RevolutBeneficiary> getBeneficiaries(String accountID) throws IOException {
        return rowMapper.getBeneficiaries(rowMapper.parse(getBeneficiariesRaw(accountID)));
    }

    /**
     * Method for sending a request to the revolut server by link
     *
     * @param link link of the endpoint
     * @return response from server
     * @throws IOException
     */
    private String sendRequest(String link) throws IOException {
        URL url = new URL(link);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + accessToken);
        connection.setRequestProperty("x-fapi-financial-id", "001580000103UAvAAM");

        // Read the response
        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            return response.toString();
        }
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
}
