package me.api.bankapi.model.revolut;


import lombok.*;
import me.api.bankapi.enums.revolut.RevolutAccountSubTypes;
import me.api.bankapi.enums.revolut.RevolutAccountTypes;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutAccount {

    private String accountID;
    private String currency;
    private RevolutAccountTypes accountType;
    private RevolutAccountSubTypes accountSubType;
    private String nickName;
    private List<RevolutAccountDetails> accounts;

}
