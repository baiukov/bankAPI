package me.api.bankapi.enums.revolut;

import java.util.Arrays;

/**
 * The enum which represents the name of the identification scheme.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public enum RevolutAccountSchemeNames {
    UK_OBIE_IBAN("UK.OBIE.IBAN"),
    UK_OBIE_SORT_CODE_ACCOUNT_NUMBER("UK.OBIE.SortCodeAccountNumber"),
    UK_ROUTING_NUMBER_ACCOUNT_NUMBER("US.RoutingNumberAccountNumber"),
    UK_OBIE_BRANCH_CODE_ACCOUNT_NUMBER("US.BranchCodeAccountNumber"),

    /**
     * Note that scheme UK.Revolut.InternalAccountId is an internal account identifier for those accounts which
     * don't have externally available identifiers. It cannot be used to send or receive funds.
     */
    UK_OBIE_REVOLUT_INTERNAL_ACCOUNT_ID("UK.Revolut.InternalAccountId");
    String name;

    RevolutAccountSchemeNames(String name) {
        this.name = name;
    }

    String getName() { return name; }

    /**
     * Method which finds a value by raw string
     *
     * @param value to be found
     * @return instance of the enum
     */
    public static RevolutAccountSchemeNames from(String value) {
        return Arrays.stream(RevolutAccountSchemeNames.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}
