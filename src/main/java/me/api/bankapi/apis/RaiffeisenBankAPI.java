package me.api.bankapi.apis;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class RaiffeisenBankAPI {
    private static String getAccessToken(String clientId, String clientSecret, String authCode, String redirectUri) throws Exception {
        String tokenUrl = "https://api.raiffeisen.com/oauth/token";

        HttpClient client = HttpClient.newHttpClient();
        String body = String.format("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s",
                authCode, redirectUri, clientId, clientSecret);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(tokenUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        JSONObject jsonResponse = new JSONObject(response.body());

        return jsonResponse.getString("access_token");
    }

    public static void main(String[] args) {
        try {
            String clientId = "your_client_id";
            String clientSecret = "your_client_secret";
            String authCode = "authorization_code_from_user_consent";
            String redirectUri = "your_redirect_uri";

            String accessToken = getAccessToken(clientId, clientSecret, authCode, redirectUri);
            System.out.println("Access Token: " + accessToken);

            getAccountBalance(accessToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void getAccountBalance(String accessToken) throws Exception {
        String balanceUrl = "https://api.raiffeisen.com/accounts/v1/balance";

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(balanceUrl))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        JSONObject balanceInfo = new JSONObject(response.body());

        System.out.println("Account Balance: " + balanceInfo.toString(2));
    }
}