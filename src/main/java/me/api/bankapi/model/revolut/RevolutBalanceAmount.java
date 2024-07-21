package me.api.bankapi.model.revolut;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 *
 * A class which represents the amount of the cash balance after a transaction entry is applied to the account.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
@AllArgsConstructor
@Getter
@Setter
@ToString
public class RevolutBalanceAmount {

    /**
     * The amount of money.
     */
    private String amount;

    /**
     * ISO 4217 currency code in upper case.
     */
    private String currency;
}
