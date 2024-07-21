package me.api.bankapi.model.revolut;

import lombok.*;
import me.api.bankapi.enums.revolut.RevolutAccountSchemeNames;

/**
 *
 * A class which represents the details to identify the account of a creditor.
 *
 * @author Aleksei Baiukov
 * @version 21.07.2024
 */
@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutCreditorAccount {

    /**
     * The name of the identification scheme.
     */
    private RevolutAccountSchemeNames schemeName;

    /**
     * The identification of the account.
     */
    private String identification;

    /**
     * The account name that the account servicing institution assigns.
     * The account name is the name or names of the account owner(s) represented at an account level.
     * The account name is not the product name or the nickname of the account.
     */
    private String name;

    /**
     * The secondary account ID that the account servicing institution assigns.
     * Building societies can use this ID to identify accounts with a roll number in addition to a sort code
     * and account number combination
     */
    private String secondaryIdentification;
}
