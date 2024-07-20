package me.api.bankapi.enums.revolut;

import java.util.Arrays;

public enum RevolutAccountSubTypes {

    CURRENT_ACCOUNT("CurrentAccount"),
    LOAN("Loan"),
    SAVINGS("Savings");

    String name;

    RevolutAccountSubTypes(String name) {
        this.name = name;
    }

    String getName() { return name; }

    public static RevolutAccountSubTypes from(String value) {
        return Arrays.stream(RevolutAccountSubTypes.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}
