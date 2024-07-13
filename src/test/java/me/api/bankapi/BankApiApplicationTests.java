package me.api.bankapi;

import me.api.bankapi.apis.RaiffeisenBankAPI;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class BankApiApplicationTests {

	@Test
	void contextLoads() {

		String secret = "99f3b619-f574-4f3e-866b-c5dddfce2de9";
		String id = "qjc35ctZipKabLMQhsg9BeN89pi0IB2u";

		RaiffeisenBankAPI api = new RaiffeisenBankAPI();

	}

}
