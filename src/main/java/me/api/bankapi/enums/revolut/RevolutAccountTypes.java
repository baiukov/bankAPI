package me.api.bankapi.enums.revolut;

import java.util.Arrays;

/**
 * The enum which represents the type of the account.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public enum RevolutAccountTypes {

    BUSINESS("Business"),
    PERSONAL("Personal");

    String name;

    RevolutAccountTypes(String name) {
        this.name = name;
    }

    String getName() { return name; }

    /**
     * Method which finds a value by raw string
     *
     * @param value to be found
     * @return instance of the enum
     */
    public static RevolutAccountTypes from(String value) {
        return Arrays.stream(RevolutAccountTypes.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}
