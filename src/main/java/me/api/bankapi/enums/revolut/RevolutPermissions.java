package me.api.bankapi.enums.revolut;

public enum RevolutPermissions {

    READ_ACCOUNT_BASIC("ReadAccountsBasic"),
    READ_ACCOUNT_DETAIL("ReadAccountsDetail"),
    READ_BALANCES("ReadBalances"),
    READ_BENEFICIARIES_BASIC("ReadBeneficiariesBasic"),
    READ_BENEFICIARIES_DETAIL("ReadBeneficiariesDetail"),
    READ_DIRECT_DEBITS("ReadDirectDebits"),
    READ_SCHEDULED_PAYMENTS_BASIC("ReadScheduledPaymentsBasic"),
    READ_SCHEDULED_PAYMENTS_DETAIL("ReadScheduledPaymentsDetail"),
    READ_STANDING_ORDER_BASIC("ReadStandingOrdersBasic"),
    READ_STANDING_ORDERS_DETAIL("ReadStandingOrdersDetail"),
    READ_TRANSACTIONS_BASIC("ReadTransactionsBasic"),
    READ_TRANSACTIONS_CREDITS("ReadTransactionsCredits", READ_TRANSACTIONS_BASIC),
    READ_TRANSACTIONS_DEBITS("ReadTransactionsDebits", READ_TRANSACTIONS_BASIC),
    READ_TRANSACTIONS_DETAIL("ReadTransactionsDetail");

    private final String value;

    private final RevolutPermissions dependency;

    RevolutPermissions(String value) {
        this(value, null);
    }

    RevolutPermissions(String value, RevolutPermissions dependency) {
        this.value = value;
        this.dependency = dependency;
    }

    public String value() {
        return value;
    }

    public RevolutPermissions dependency() {
        return dependency;
    }

}
