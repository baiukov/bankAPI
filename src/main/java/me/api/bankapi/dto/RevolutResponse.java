package me.api.bankapi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.json.JSONObject;

@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
public class RevolutResponse {

    private JSONObject data;
    private JSONObject risk;
    private JSONObject links;
    private JSONObject meta;

}
