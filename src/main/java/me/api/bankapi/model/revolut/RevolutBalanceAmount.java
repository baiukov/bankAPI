package me.api.bankapi.model.revolut;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@Setter
@ToString
public class RevolutBalanceAmount {
    private String amount;
    private String currency;
}
