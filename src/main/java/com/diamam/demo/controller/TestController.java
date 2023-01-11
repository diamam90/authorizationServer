package com.diamam.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class TestController {

    @GetMapping("/")
    public String salam(){
        return "SALAM ALEIKUM BRAT";
    }
}
