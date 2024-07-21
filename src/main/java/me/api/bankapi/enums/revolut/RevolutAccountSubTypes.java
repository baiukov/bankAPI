package me.api.bankapi.enums.revolut;

import java.util.Arrays;

/**
 * The enum which represents the subtype of the account.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public enum RevolutAccountSubTypes {

    CURRENT_ACCOUNT("CurrentAccount"),
    LOAN("Loan"),
    SAVINGS("Savings");

    String name;

    RevolutAccountSubTypes(String name) {
        this.name = name;
    }

    String getName() { return name; }

    /**
     * Method which finds a value by raw string
     *
     * @param value to be found
     * @return instance of the enum
     */
    public static RevolutAccountSubTypes from(String value) {
        return Arrays.stream(RevolutAccountSubTypes.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}
