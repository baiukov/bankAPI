package me.api.bankapi.model.revolut;


import lombok.*;
import me.api.bankapi.enums.revolut.RevolutAccountSubTypes;
import me.api.bankapi.enums.revolut.RevolutAccountTypes;

import java.util.List;

/**
 *
 * A class which represents an account of revolut user.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutAccount {

    /**
     * The unique and immutable ID to identify the account resource. This ID has no meaning to the account owner.
     */
    private String accountID;

    /**
     *  The currency that the account is held in (ISO 4217 currency code in upper case).
     *  This value is used only when one account number covers multiple accounts for different currencies,
     *  and the initiating party needs to identify which currency to use for settlement on the account.
     */
    private String currency;

    /**
     * The type of the account.
     */
    private RevolutAccountTypes accountType;

    /**
     * The subtype of the account.
     */
    private RevolutAccountSubTypes accountSubType;

    /**
     * The nickname of the account that the account owner assigns to easily identify the account.
     */
    private String nickName;

    /**
     *  List of the account details to identify an account.
     */
    private List<RevolutAccountDetails> accounts;

}
