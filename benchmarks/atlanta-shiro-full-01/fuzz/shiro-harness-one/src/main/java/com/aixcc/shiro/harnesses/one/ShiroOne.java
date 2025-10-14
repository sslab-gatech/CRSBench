package com.aixcc.shiro.harnesses.one;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.nio.ByteBuffer;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.codec.Base64;
import com.code_intelligence.jazzer.api.BugDetectors;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class ShiroOne {

    final static String baseUrl = "http://localhost:8080";

    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        BugDetectors.allowNetworkConnections((String h, Integer p) -> h.endsWith("localhost"));
        ConfigurableApplicationContext ctx = SpringApplication.run(ShiroApp.class, new String[]{});
        try {
            new ShiroOne().fuzz(data);
        } finally {
            ctx.close();
        }
    }

    public void login(String username, String password, String rememberme, byte[] data) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        if (data.length > 0) {
            headers.add("Cookie", "rememberMe=" + encrypt(data));
        }

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", username);
        requestBody.add("password", password);
        requestBody.add("rememberme", rememberme);

        String url = baseUrl + "/doLogin";
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.exchange(
            url,
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers),
            String.class
        );
    }

    public String encrypt(byte[] data) {
        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));
        ByteSource ciphertext = aes.encrypt(data, key);
        return ciphertext.toString();
    }

    public void fuzz(byte[] data) throws Throwable {
        int cur = 0;
        ByteBuffer buf = ByteBuffer.wrap(data);

        if (data.length < Integer.BYTES) {
            return;
        }

        int count = buf.getInt(cur);
        cur += Integer.BYTES;
        if (count > 255) {
            return;
        }

        List<String> args = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            if (data.length - cur < Integer.BYTES * 2) {
                return;
            }
            int picker = buf.getInt(cur);
            cur += Integer.BYTES;
            int buf_size = buf.getInt(cur);
            cur += Integer.BYTES;
            if (data.length - cur < buf_size || buf_size < 0) {
                return;
            }

            byte[] whole = Arrays.copyOfRange(data, cur, cur + buf_size);
            cur += buf_size;
            
            switch (picker) {
                case 313: {
                    encrypt(whole);
                    break;
                }
                case 4912: {
                    if (args.size() < 3) {
                        continue;
                    }
                    login(args.get(0), args.get(1), args.get(2), whole);
                    break;
                }
                case 84778:
                    args.add(new String(whole));
                    break;
                case 9949556:
                    args.clear();
                    break;
                default:
                    throw new Exception("unsupported");
            }
        }
    }
}
