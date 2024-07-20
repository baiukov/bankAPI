package me.api.bankapi.enums;

public enum SupportedBanks {

    REVOLUT("Revolut"),
    UNKNOWN("Uknown");

    private final String value;

    SupportedBanks(String name) {
        this.value = name;
    }

    public String value() {
        return value;
    }

}
