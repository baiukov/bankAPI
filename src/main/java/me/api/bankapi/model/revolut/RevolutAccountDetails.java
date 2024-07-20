package me.api.bankapi.model.revolut;


import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
@ToString
public class RevolutAccountDetails {
    private String schemeName;
    private String identification;
    private String name;
    private String secondaryIdentification;
}
