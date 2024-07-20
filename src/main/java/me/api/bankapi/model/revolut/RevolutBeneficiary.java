package me.api.bankapi.model.revolut;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@AllArgsConstructor
@ToString
public class RevolutBeneficiary {
    private String accountID;
    private String beneficiaryID;
    private RevolutCreditorAccount creditorAccount;

}
