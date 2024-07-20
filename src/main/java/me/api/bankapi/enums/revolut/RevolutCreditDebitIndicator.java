package me.api.bankapi.enums.revolut;

import java.util.Arrays;

public enum RevolutCreditDebitIndicator {

    CREDIT("Credit"),
    DEBIT("Debit");

    String name;

    RevolutCreditDebitIndicator(String name) {
        this.name = name;
    }

    String getName() { return name; }

    public static RevolutCreditDebitIndicator from(String value) {
        return Arrays.stream(RevolutCreditDebitIndicator.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}

