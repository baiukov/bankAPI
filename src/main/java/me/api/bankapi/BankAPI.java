package me.api.bankapi;

import me.api.bankapi.apis.RevolutAPI;
import me.api.bankapi.enums.revolut.RevolutPermissions;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BankAPI {

	public static void main(String[] args) {
//		SpringApplication.run(BankAPI.class, args);

		try {
			RevolutAPI revolutAPI;
			revolutAPI = new RevolutAPI.RevolutAPIBuilder()
					.setTransportCertificatePath("certificates/revolut/transport.pem")
					.setPrivateKeyPath("certificates/revolut/private.key")
					.setTrustStorePath("certificates/revolut/truststore.jks")
					.setIsSandbox(true)
					.setClientID("21c31458-0a66-4ac6-8093-f45e2aba7146")
					.setKid("-zGZ5dHlNlSb9j3EHlm7PO_V_vg")
					.setAccessToken("oa_sand_uBfiqH58__kjbWX0pxNN6bnSZ3EfywzUSTZ3tiuXSfQ")
					.setPermissions(RevolutPermissions.READ_ACCOUNT_BASIC,
							RevolutPermissions.READ_ACCOUNT_DETAIL,
							RevolutPermissions.READ_BALANCES,
							RevolutPermissions.READ_BENEFICIARIES_DETAIL,
							RevolutPermissions.READ_BENEFICIARIES_BASIC
					)
					.build();
//			revolutAPI.setAccessToken("oa_sand_oJMKYw7CxZNPnb9gl45HqZ26nWopPSc48PBjJmrTSec");
//			System.out.println(Desktop.isDesktopSupported());
//			JSONObject jsonObject = new JSONObject(revolutAPI.getToken());
//			System.out.println(jsonObject);
//			JSONObject consent = new JSONObject(revolutAPI.getConsent(jsonObject));
//			System.out.println(consent);
//			System.out.println("ConsentID: " + consent.getJSONObject("Data").getString("ConsentId"));
//			System.out.println(revolutAPI.getJWTParameters("https://127.0.0.1:5500",
//					consent.getJSONObject("Data").getString("ConsentId")));
//			System.out.println(revolutAPI.getConsentURL("https://google.com"));
//			System.out.println(revolutAPI.getAccessToken("oa_sand_g78btPBVYrJ_2yvIf-lL67mcDgUSADQ40mD6BYaQSEw"));
//			System.out.println(revolutAPI.getAccountsRaw());
			System.out.println(revolutAPI.getAccounts());
//			System.out.println(revolutAPI.getBalance("03b7dc99-39c8-4d56-b145-af71065ea532"));
			System.out.println(revolutAPI.getBeneficiaries("03b7dc99-39c8-4d56-b145-af71065ea532"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

    }


}
