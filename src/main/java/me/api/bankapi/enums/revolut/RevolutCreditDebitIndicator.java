package me.api.bankapi.enums.revolut;

import java.util.Arrays;

/**
 * The enum which represents indication whether the balance is a credit or a debit balance.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public enum RevolutCreditDebitIndicator {

    CREDIT("Credit"),
    DEBIT("Debit");

    String name;

    RevolutCreditDebitIndicator(String name) {
        this.name = name;
    }

    String getName() { return name; }

    /**
     * Method which finds a value by raw string
     *
     * @param value to be found
     * @return instance of the enum
     */
    public static RevolutCreditDebitIndicator from(String value) {
        return Arrays.stream(RevolutCreditDebitIndicator.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}

