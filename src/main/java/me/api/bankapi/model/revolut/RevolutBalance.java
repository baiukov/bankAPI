package me.api.bankapi.model.revolut;

import lombok.*;
import me.api.bankapi.enums.revolut.RevolutBalanceType;
import me.api.bankapi.enums.revolut.RevolutCreditDebitIndicator;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutBalance {
    private String accountID;
    private RevolutCreditDebitIndicator creditDebitIndicator;
    private RevolutBalanceType type;
    private LocalDateTime dateTime;
    private RevolutBalanceAmount amount;
}
