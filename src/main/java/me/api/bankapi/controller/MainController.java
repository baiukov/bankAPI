package me.api.bankapi.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class MainController {

    @PostMapping("/code")
    public void postCode(String code) {
        System.out.println(code);
    }

}
