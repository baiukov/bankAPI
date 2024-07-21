package me.api.bankapi.model.revolut;

import lombok.*;
import me.api.bankapi.enums.revolut.RevolutBalanceType;
import me.api.bankapi.enums.revolut.RevolutCreditDebitIndicator;

import java.time.LocalDateTime;

/**
 *
 * A class which represents a balance of revolut user's account.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutBalance {

    /**
     * The unique and immutable ID to identify the account resource. This ID has no meaning to the account owner.
     */
    private String accountID;

    /**
     * Indicates whether the balance is a credit or a debit balance.
     * Note: a zero balance is considered a credit balance.
     */
    private RevolutCreditDebitIndicator creditDebitIndicator;

    /**
     * The balance type.
     */
    private RevolutBalanceType type;

    /**
     * The date and time for the balance.
     * All dates in the JSON payloads are represented in ISO 8601 date-time format and then mapped to the LocalDateTime.
     * All date-time fields in responses must include the timezone in JSON.
     */
    private LocalDateTime dateTime;

    /**
     * The amount of the cash balance after a transaction entry is applied to the account.
     */
    private RevolutBalanceAmount amount;
}
