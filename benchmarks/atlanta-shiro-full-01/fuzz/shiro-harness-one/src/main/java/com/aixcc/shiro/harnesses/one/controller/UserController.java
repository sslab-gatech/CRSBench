package com.aixcc.shiro.harnesses.one.controller;

import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class UserController {
    @PostMapping("/doLogin")
    public String doLoginPage(@RequestParam("username") String username, @RequestParam("password") String password, @RequestParam(name="rememberme", defaultValue = "") String rememberMe) {
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(new UsernamePasswordToken(username, password, rememberMe.equals("remember-me")));
        } catch (AuthenticationException e) {
            return "redirect:/login";
        }

        return "redirect:/";
    }

    @RequestMapping("/")
    public String helloPage() {
        return "hello";
    }

    @RequestMapping("/unauth")
    public String errorPage() {
        return "error";
    }

    @RequestMapping("/login")
    public String loginPage() {
        return "login";
    }

    @RequestMapping("/emfndhk")
    public String emfndhk(@RequestParam("data") String data) {
        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));
        ByteSource ciphertext = aes.encrypt(data.getBytes(), key);
        return ciphertext.toString();
    }
}
