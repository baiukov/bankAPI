package me.api.bankapi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.json.JSONObject;

/**
 *
 *  Data transfer object class which represents a response got from revolut webserver.
 *
 * @author Aleksei_Baiukov
 * @version 21.07.2024
 */
@Getter
@Setter
@AllArgsConstructor
@Builder(toBuilder = true)
public class RevolutResponse {

    /**
     * Different data's objects, which depends on sent request
     */
    private JSONObject data;

    /**
     * The Risk section contains the risk indicators that the initiating party sends to the ASPSP,
     * which can be used to specify additional details for risk scoring for account information.
     */
    private JSONObject risk;

    /**
     * Links relevant to the payload.
     */
    private JSONObject links;

    /**
     * Meta data relevant to the payload.
     */
    private JSONObject meta;

}
