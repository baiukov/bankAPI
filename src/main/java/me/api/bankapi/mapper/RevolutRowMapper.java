package me.api.bankapi.mapper;

import me.api.bankapi.dto.RevolutResponse;
import me.api.bankapi.enums.revolut.*;
import me.api.bankapi.model.revolut.*;
import org.json.JSONArray;
import org.json.JSONObject;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.StreamSupport;

public class RevolutRowMapper {

    public RevolutResponse parse(String raw) {
        JSONObject dto = new JSONObject(raw);
        return RevolutResponse.builder()
                .data(dto.getJSONObject("Data"))
                .risk(dto.has("Risk") ? dto.getJSONObject("Risk") : null)
                .links(dto.getJSONObject("Links"))
                .meta(dto.getJSONObject("Meta"))
                .build();
    }

    public List<RevolutAccount> getAccounts(RevolutResponse response) {
        JSONArray jsonAccounts = response.getData().getJSONArray("Account");
        return StreamSupport.stream(jsonAccounts.spliterator(), false)
                .map(JSONObject.class::cast)
                .map(jsonObject -> RevolutAccount.builder()
                        .accountID(jsonObject.getString("AccountId"))
                        .currency(jsonObject.getString("Currency"))
                        .accountType(RevolutAccountTypes.from(jsonObject.getString("AccountType")))
                        .accountSubType(RevolutAccountSubTypes.from(jsonObject.getString("AccountSubType")))
                        .nickName(jsonObject.has("NickName") ? jsonObject.getString("NickName") : null)
                        .accounts(getAccountDetails(jsonObject.getJSONArray("Account")))
                        .build()
                )
                .toList();
    }

    public List<RevolutAccountDetails> getAccountDetails(JSONArray accountObjects) {
        return StreamSupport.stream(accountObjects.spliterator(), false)
                .map(JSONObject.class::cast)
                .map(object -> RevolutAccountDetails.builder()
                        .schemeName(object.getString("SchemeName"))
                        .identification(object.getString("Identification"))
                        .name(object.getString("Name"))
                        .secondaryIdentification(object.has("SecondaryIdentification") ?
                                object.getString("SecondaryIdentification") : null)
                        .build())
                .toList();
    }

    public RevolutBalance getBalance(RevolutResponse response) {
        JSONArray jsonObjects = response.getData().getJSONArray("Balance");
        return StreamSupport.stream(jsonObjects.spliterator(), false)
                .map(JSONObject.class::cast)
                .map(jsonObject -> RevolutBalance.builder()
                        .accountID(jsonObject.getString("AccountId"))
                        .amount(new RevolutBalanceAmount(
                                jsonObject.getJSONObject("Amount").getString("Amount"),
                                jsonObject.getJSONObject("Amount").getString("Currency")))
                        .creditDebitIndicator(RevolutCreditDebitIndicator.from(
                                jsonObject.getString("CreditDebitIndicator")))
                        .type(RevolutBalanceType.from(jsonObject.getString("Type")))
                        .dateTime(LocalDateTime.parse(
                                jsonObject.getString("DateTime"),
                                DateTimeFormatter.ISO_OFFSET_DATE_TIME))
                        .build()
                )
                .findFirst()
                .orElse(null);
    }

    public List<RevolutBeneficiary> getBeneficiaries(RevolutResponse response) {
        JSONArray jsonObjects = response.getData().getJSONArray("Beneficiary");
        return StreamSupport.stream(jsonObjects.spliterator(), false)
                .map(JSONObject.class::cast)
                .map(jsonObject -> new RevolutBeneficiary(
                        jsonObject.getString("AccountId"),
                        jsonObject.getString("BeneficiaryId"),
                        jsonObject.has("CreditorAccount") ? RevolutCreditorAccount.builder()
                                .schemeName(CreditorAccountSchemeNames.from(
                                        jsonObject.getJSONObject("CreditorAccount").getString("SchemeName")))
                                .identification(jsonObject.getJSONObject("CreditorAccount")
                                        .getString("Identification"))
                                .name(jsonObject.getJSONObject("CreditorAccount").has("Name") ?
                                        jsonObject.getJSONObject("CreditorAccount").getString("Name") : null)
                                .build() : null
                ))
                .toList();
    }

}
