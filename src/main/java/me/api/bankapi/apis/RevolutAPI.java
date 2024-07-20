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

public class RevolutAPI {

    private X509Certificate transportCertificate;

    private PrivateKey privateKey;

    private TrustManagerFactory trustManagerFactory;

    private boolean isSandbox;
    private String clientID;

    private SSLContext sslContext;

    private String kid;

    private String consentExpiration;
    private String transactionFrom;
    private String transactionTo;


    private final List<RevolutPermissions> consentPermissions = new ArrayList<>();

    private final String sandboxTokenURL = "https://sandbox-oba-auth.revolut.com/token";
    private final String sandboxConsentURL = "https://sandbox-oba.revolut.com/account-access-consents";
    private final String sandboxUserConsentURL = "https://sandbox-oba.revolut.com/ui/index.html?response_type=code%%20id_token&scope=accounts&redirect_uri=%s&client_id=%s&request=%s&state=example_state";
    private final String sandboxURL = "https://sandbox-oba.revolut.com/";
    private final String prodTokenURL = "https://oba-auth.revolut.com/token";
    private final String prodConsentURL = "https://oba.revolut.com/account-access-consents";
    private final String prodUserConsentURL = "https://oba.revolut.com/ui/index.html?response_type=code%20id_token&scope=accounts&redirect_uri=%s&client_id=%s&request=%s&state=example_state";
    private final String prodURL = "https://oba.revolut.com/";

    private String accessToken;

    private RevolutAPI(RevolutAPIBuilder builder)
            throws MalformedBuilder, CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, KeyStoreException, UnrecoverableKeyException, KeyManagementException
    {
        this.isSandbox = builder.isSandbox;
        if (builder.accessToken != null) {
            this.accessToken = builder.accessToken;
            return;
        }

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

        this.sslContext = builder.sslContext == null ? getSSLContext() : builder.sslContext;
        this.clientID = builder.clientID;
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

        public RevolutAPIBuilder setTransportCertificate(X509Certificate transportCertificate) {
            this.transportCertificate = transportCertificate;
            return this;
        }

        public RevolutAPIBuilder setTransportCertificateFile(InputStream transportCertificateFile) {
            this.transportCertificateFile = transportCertificateFile;
            return this;
        }

        public RevolutAPIBuilder setTransportCertificatePath(String transportCertificatePath) {
            this.transportCertificatePath = transportCertificatePath;
            return this;
        }

        public RevolutAPIBuilder setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public RevolutAPIBuilder setPrivateKeyFile(InputStream privateKeyFile) {
            this.privateKeyFile = privateKeyFile;
            return this;
        }

        public RevolutAPIBuilder setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
            return this;
        }

        public RevolutAPIBuilder setTrustManagerFactory(TrustManagerFactory trustManagerFactory) {
            this.trustManagerFactory = trustManagerFactory;
            return this;
        }

        public RevolutAPIBuilder setTrustStoreFile(InputStream trustStoreFile) {
            this.trustStoreFile = trustStoreFile;
            return this;
        }

        public RevolutAPIBuilder setTrustStorePath(String trustStorePath) {
            this.trustStorePath = trustStorePath;
            return this;
        }

        public RevolutAPIBuilder setIsSandbox(boolean isSandbox) {
            this.isSandbox = isSandbox;
            return this;
        }

        public RevolutAPIBuilder setClientID(String clientID) {
            this.clientID = clientID;
            return this;
        }

        public RevolutAPIBuilder setSSLContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        public RevolutAPIBuilder setConsentExpiration(LocalDateTime consentExpiration) {
            this.consentExpiration = consentExpiration;
            return this;
        }

        public RevolutAPIBuilder setConsentExpirationString(String consentExpirationString) {
            this.consentExpirationString = consentExpirationString;
            return this;
        }

        public RevolutAPIBuilder setConsentExpirationTimestamp(Instant consentExpirationTimestamp) {
            this.consentExpirationTimestamp = consentExpirationTimestamp;
            return this;
        }

        public RevolutAPIBuilder setTransactionToDate(LocalDateTime transactionTo) {
            this.transactionTo = transactionTo;
            return this;
        }

        public RevolutAPIBuilder setTransactionToDateString(String transactionToString) {
            this.transactionToString = transactionToString;
            return this;
        }

        public RevolutAPIBuilder setTransactionToDateTimestamp(Instant transactionFromTimestamp) {
            this.transactionFromTimestamp = transactionFromTimestamp;
            return this;
        }

        public RevolutAPIBuilder setTransactionFromDate(LocalDateTime transactionFrom) {
            this.transactionFrom = transactionFrom;
            return this;
        }

        public RevolutAPIBuilder setTransactionFromDateString(String transactionFromString) {
            this.transactionFromString = transactionFromString;
            return this;
        }

        public RevolutAPIBuilder setTransactionFromTimestamp(Instant transactionFromTimestamp) {
            this.transactionFromTimestamp = transactionFromTimestamp;
            return this;
        }

        public RevolutAPIBuilder setPermissions(RevolutPermissions ... permission) {
            this.consentPermission = List.of(permission);
            return this;
        }

        public RevolutAPIBuilder setKid(String kid) {
            this.kid = kid;
            return this;
        }

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

    private InputStream getFile(String path) throws CertificateException {
        InputStream fileStream = RevolutRequest.class.getClassLoader().getResourceAsStream(path);
        if (fileStream == null) {
            throw new CertificateException("Transport certificate file not found");
        }
        return fileStream;
    }

    private PrivateKey getPrivateKey(InputStream keyFileStream) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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

    private TrustManagerFactory getTrustManagerFactory(InputStream trustStoreFile, String keyStorePassword)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException
    {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(trustStoreFile, keyStorePassword.toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return trustManagerFactory;
    }

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

    public String getConsent(JSONObject token) throws IOException {
        return getConsent(token.getString("access_token"));
    }

    public String getConsent(String token) throws IOException {
        URL url = new URL(isSandbox ? sandboxConsentURL : prodConsentURL);
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

        // Write the request body to the connection
        try (OutputStream outputStream = connection.getOutputStream()) {
            byte[] input = request.toString().getBytes(StandardCharsets.UTF_8);
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
    }

    public String getConsent() throws IOException {
        JSONObject token = new JSONObject(getToken());
        return getConsent(token.getString("access_token"));
    }


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

    public String getJWTParameters(String redirectURL) throws IOException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        JSONObject consent = new JSONObject(getConsent());
        JSONObject data = consent.getJSONObject("Data");
        if (data == null) return null;
        String consentId = data.getString("ConsentId");
        return getJWTParameters(redirectURL, consentId);
    }

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

    public String getAccountsRaw() throws IOException {
        URL url = new URL((isSandbox ? sandboxURL : prodURL) + "accounts");
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

    public List<RevolutAccount> getAccounts() throws IOException {
        return RevolutRowMapper.getAccounts(getAccountsRaw());
    }

    public String getAccountRaw(String accountID) throws IOException {
        URL url = new URL(String.format("%s/accounts/%s", isSandbox ? sandboxURL : prodURL, accountID));
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + accessToken);
        connection.setRequestProperty("x-fapi-financial-id", "001580000103UAvAAM");

        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            return response.toString();
        }
    }

    public RevolutAccount getAccount(String accountID) throws IOException {
        return RevolutRowMapper.getAccounts(getAccountRaw(accountID)).stream().findFirst().orElse(null);
    }

    public String getBalanceRaw(String accountID) throws IOException {
        URL url = new URL(String.format("%saccounts/%s/balances", isSandbox ? sandboxURL : prodURL, accountID));
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

    public RevolutBalance getBalance(String accountID) throws IOException {
        return RevolutRowMapper.getBalance(getBalanceRaw(accountID));
    }

    public String getBeneficiariesRaw(String accountID) throws IOException {
        URL url = new URL(String.format("%saccounts/%s/beneficiaries", isSandbox ? sandboxURL : prodURL, accountID));
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

    public List<RevolutBeneficiary> getBeneficiaries(String accountID) throws IOException {
        return RevolutRowMapper.getBeneficiaries(getBeneficiariesRaw(accountID));
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
