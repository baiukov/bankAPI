package me.api.bankapi.enums.revolut;

import java.util.Arrays;

/**
 * The enum which represents the balance type.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
public enum RevolutBalanceType {

    INTERIM_AVAILABLE("InterimAvailable"),
    INTERIM_BOOKED("InterimBooked"),
    CLOSING_AVAILABLE("ClosingAvailable"),
    CLOSING_BOOKED("ClosingBooked"),
    CLOSING_CLEARED("ClosingCleared"),
    EXPECTED("Expected"),
    FORWARD_AVAILABLE("ForwardAvailable"),
    INFORMATION("Information"),
    INTERIM_CLEARED("InterimCleared"),
    OPENING_AVAILABLE("OpeningAvailable"),
    OPENING_BOOKED("OpeningBooked"),
    OPENING_CLEARED("OpeningCleared"),
    PREVIOUSLY_CLOSED_BOOKED("PreviouslyClosedBooked");

    String name;

    RevolutBalanceType(String name) {
        this.name = name;
    }

    String getName() { return name; }

    /**
     * Method which finds a value by raw string
     *
     * @param value to be found
     * @return instance of the enum
     */
    public static RevolutBalanceType from(String value) {
        return Arrays.stream(RevolutBalanceType.values())
                .filter(v -> v.name().equals(value))
                .findFirst()
                .orElse(null);
    }
}

