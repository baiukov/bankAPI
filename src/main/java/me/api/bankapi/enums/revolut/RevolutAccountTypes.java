package me.api.bankapi.enums.revolut;

import java.util.Arrays;

public enum RevolutAccountTypes {

    BUSINESS("Business"),
    PERSONAL("Personal");

    String name;

    RevolutAccountTypes(String name) {
        this.name = name;
    }

    String getName() { return name; }

    public static RevolutAccountTypes from(String value) {
        return Arrays.stream(RevolutAccountTypes.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}
