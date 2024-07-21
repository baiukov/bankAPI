package me.api.bankapi.model.revolut;

import lombok.*;

/**
 *
 * A class which represents a beneficiary of a specific user account.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
@Getter
@Setter
@AllArgsConstructor
@ToString
@EqualsAndHashCode
public class RevolutBeneficiary {

    /**
     * The unique and immutable ID to identify the account resource. This ID has no meaning to the account owner.
     */
    private String accountID;

    /**
     * The unique and immutable ID to identify the beneficiary resource. This ID has no meaning to the account owner.
     */
    private String beneficiaryID;

    /**
     * The details to identify the account.
     */
    private RevolutCreditorAccount creditorAccount;

}
