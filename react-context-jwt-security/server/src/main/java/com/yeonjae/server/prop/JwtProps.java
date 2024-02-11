package com.yeonjae.server.prop;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties("com.yeonjae.server")
public class JwtProps {
    private String secretKey;
}
