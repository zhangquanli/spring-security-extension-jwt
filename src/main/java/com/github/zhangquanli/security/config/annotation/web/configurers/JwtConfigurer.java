package com.github.zhangquanli.security.config.annotation.web.configurers;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class JwtConfigurer {
    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
