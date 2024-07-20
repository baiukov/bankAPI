package me.api.bankapi.model.revolut;

import lombok.*;
import me.api.bankapi.enums.revolut.CreditorAccountSchemeNames;

@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutCreditorAccount {
    private CreditorAccountSchemeNames schemeName;
    private String identification;
    private String name;
    private String secondaryIdentification;
}
