package me.api.bankapi.mapper;

import me.api.bankapi.dto.RevolutResponse;
import me.api.bankapi.enums.revolut.*;
import me.api.bankapi.model.revolut.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RevolutRowMapperTest {

    private final RevolutRowMapper revolutRowMapper = new RevolutRowMapper();

    @Test
    void givenRawResponseJSONObject_ShouldMapIntoResponse() throws JSONException {
        JSONObject data = new JSONObject().put("testData", 1);
        JSONObject risk = new JSONObject().put("risk", new JSONObject());
        JSONObject links = new JSONObject().put("self", "https://oba.revolut.com/");
        JSONObject meta = new JSONObject().put("TotalPages", 1);

        RevolutResponse expected = RevolutResponse.builder().data(data).risk(risk)
                .links(links).meta(meta).build();

        JSONObject jsonData = new JSONObject()
                .put("Data", data)
                .put("Risk", risk)
                .put("Links", links)
                .put("Meta", meta);

        assertEquals(expected.toString(), revolutRowMapper.parse(jsonData.toString()).toString());
    }

    @Test
    void givenARawJSONObject_shouldMapIntoExpectedBalance() throws JSONException, JSONException {
        String id = "randomID";
        RevolutCreditDebitIndicator creditDebitIndicator = RevolutCreditDebitIndicator.DEBIT;
        RevolutBalanceType type = RevolutBalanceType.INTERIM_AVAILABLE;
        LocalDateTime dateTime = LocalDateTime.of(2022, 9, 22, 8, 32, 2, 775972000);
        RevolutBalanceAmount amount = new RevolutBalanceAmount(100.0, "USD");

        RevolutBalance expected = RevolutBalance.builder()
                .accountID(id)
                .creditDebitIndicator(creditDebitIndicator)
                .type(type)
                .dateTime(dateTime)
                .amount(amount)
                .build();

        JSONObject amountObj = new JSONObject()
                .put("Amount", amount.getAmount())
                .put("Currency", amount.getCurrency());
        JSONObject balance = new JSONObject()
                .put("AccountId", id)
                .put("CreditDebitIndicator", creditDebitIndicator.getName())
                .put("Type", type.getName())
                .put("DateTime", "2022-09-22T08:32:02.775972Z")
                .put("Amount", amountObj);
        List<JSONObject> myArrayList = List.of(balance);
        JSONArray balances = new JSONArray(myArrayList);
        JSONObject jsonObject = new JSONObject()
                .put("Balance", balances);

        RevolutResponse response = RevolutResponse.builder().data(jsonObject).build();

        assertEquals(expected, revolutRowMapper.getBalance(response));
    }

    @Test
    void givenRawJsonObjectWithAccounts_ShouldMapIntoExpectedAccountList() throws JSONException {
        Object[] accountDetailsData = getAccountDetailsData().get();
        List<RevolutAccountDetails> accountDetails;
        accountDetails = (List<RevolutAccountDetails>) accountDetailsData[0];

        List<RevolutAccount> expected = new ArrayList<>();
        String accountId1 = UUID.randomUUID().toString();
        String currency1 = "USD";
        RevolutAccountTypes accountType1 = RevolutAccountTypes.BUSINESS;
        RevolutAccountSubTypes accountSubtype1 = RevolutAccountSubTypes.CURRENT_ACCOUNT;
        String nickName1 = "randomNickname1";

        expected.add(RevolutAccount.builder()
                .accountID(accountId1)
                .currency(currency1)
                .accountType(accountType1)
                .accountSubType(accountSubtype1)
                .nickName(nickName1)
                .accounts(accountDetails)
                .build());

        String accountId2 = UUID.randomUUID().toString();
        String currency2 = "EUR";
        RevolutAccountTypes accountType2 = RevolutAccountTypes.PERSONAL;
        RevolutAccountSubTypes accountSubtype2 = RevolutAccountSubTypes.LOAN;

        expected.add(RevolutAccount.builder()
                .accountID(accountId2)
                .currency(currency2)
                .accountType(accountType2)
                .accountSubType(accountSubtype2)
                .accounts(new ArrayList<>())
                .build());

        JSONObject account1 = new JSONObject()
                .put("AccountId", accountId1)
                .put("Currency", currency1)
                .put("AccountType", accountType1.getName())
                .put("AccountSubType", accountSubtype1.getName())
                .put("NickName", nickName1)
                .put("Account", accountDetailsData[1]);

        JSONObject account2 = new JSONObject()
                .put("AccountId", accountId2)
                .put("Currency", currency2)
                .put("AccountType", accountType2.getName())
                .put("AccountSubType", accountSubtype2.getName())
                .put("Account", new JSONArray());

        JSONArray objects = new JSONArray().put(account1).put(account2);
        RevolutResponse response = RevolutResponse.builder().data(new JSONObject().put("Account", objects)).build();

        assertEquals(expected, revolutRowMapper.getAccounts(response));

    }

    @Test
    void givenRawJsonObjectWithAccountDetails_ShouldMapIntoExpectedAccountDetailsList() throws JSONException {
        Object[] testData = getAccountDetailsData().get();
        assertEquals(testData[0], revolutRowMapper.getAccountDetails((JSONArray) testData[1]));
    }

    @Test
    void givenBeneficiariesRawJsonArray_ShouldMapIntoBeneficiariesObjects() throws JSONException {
        List<RevolutBeneficiary> expected = new ArrayList<>();
        String accountId1 = UUID.randomUUID().toString();
        String beneficiaryId1 = UUID.randomUUID().toString();
        RevolutAccountSchemeNames schemeName = RevolutAccountSchemeNames.UK_OBIE_IBAN;
        String identification = "11223321325698";
        String name = "Receiver Co.";
        RevolutCreditorAccount revolutCreditorAccount1 = RevolutCreditorAccount.builder()
                .schemeName(schemeName)
                .identification(identification)
                .name(name)
                .build();
        expected.add(new RevolutBeneficiary(accountId1, beneficiaryId1, revolutCreditorAccount1));

        String accountId2 = UUID.randomUUID().toString();
        String beneficiaryId2 = UUID.randomUUID().toString();
        expected.add(new RevolutBeneficiary(accountId2, beneficiaryId2, null));

        JSONObject beneficiary1 = new JSONObject()
                .put("AccountId", accountId1)
                .put("BeneficiaryId", beneficiaryId1)
                .put("CreditorAccount", new JSONObject()
                        .put("SchemeName", schemeName.getName())
                        .put("Identification", identification)
                        .put("Name", name)
                );

        JSONObject beneficiary2 = new JSONObject()
                .put("AccountId", accountId2)
                .put("BeneficiaryId", beneficiaryId2);

        JSONArray objects = new JSONArray().put(beneficiary1).put(beneficiary2);
        RevolutResponse response = RevolutResponse.builder().data(new JSONObject().put("Beneficiary", objects)).build();

        assertEquals(expected, revolutRowMapper.getBeneficiaries(response));
    }

    private Arguments getAccountDetailsData() throws JSONException {
        List<RevolutAccountDetails> expected = new ArrayList<>();
        RevolutAccountSchemeNames schemeName1 = RevolutAccountSchemeNames.UK_OBIE_IBAN;
        String identification1 = "GB95REVO00997053872360";
        String name1 = "John Smith";

        expected.add(RevolutAccountDetails.builder()
                .schemeName(schemeName1)
                .identification(identification1)
                .name(name1)
                .build()
        );

        RevolutAccountSchemeNames schemeName2 = RevolutAccountSchemeNames.UK_OBIE_REVOLUT_INTERNAL_ACCOUNT_ID;
        String identification2 = "00000001611667";
        String name2 = "randomName2";
        String secIdent2 = "randomSecIdent";

        expected.add(RevolutAccountDetails.builder()
                .schemeName(schemeName2)
                .identification(identification2)
                .name(name2)
                .secondaryIdentification(secIdent2)
                .build()
        );

        JSONObject details1 = new JSONObject()
                .put("SchemeName", schemeName1.getName())
                .put("Identification", identification1)
                .put("Name", name1);

        JSONObject details2 = new JSONObject()
                .put("SchemeName", schemeName2.getName())
                .put("Identification", identification2)
                .put("Name", name2)
                .put("SecondaryIdentification", secIdent2);

        JSONArray objects = new JSONArray().put(details1).put(details2);

        return Arguments.of(expected, objects);
    }

}
