package me.api.bankapi.enums.revolut;

import java.util.Arrays;

public enum CreditorAccountSchemeNames {
    UK_OBIE_IBAN("UK.OBIE.IBAN"),
    UK_OBIE_SORT_CODE_ACCOUNT_NUMBER("UK.OBIE.SortCodeAccountNumber"),
    UK_ROUTING_NUMBER_ACCOUNT_NUMBER("US.RoutingNumberAccountNumber"),
    UK_OBIE_BRANCH_CODE_ACCOUNT_NUMBER("US.BranchCodeAccountNumber"),
    UK_OBIE_REVOLUT_INTERNAL_ACCOUNT_ID("UK.Revolut.InternalAccountId");
    String name;

    CreditorAccountSchemeNames(String name) {
        this.name = name;
    }

    String getName() { return name; }

    public static CreditorAccountSchemeNames from(String value) {
        return Arrays.stream(CreditorAccountSchemeNames.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}
