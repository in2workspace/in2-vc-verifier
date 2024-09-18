package es.in2.vcverifier.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;

@Component
@Getter
@Setter
@ConfigurationProperties("validation-policies")
public class ValidationPoliciesConfigProperties {
    private final ResourceLoader resourceLoader;

    private String defaultPolicyPath;
    @Autowired
    public ValidationPoliciesConfigProperties(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public InputStream getDefaultPolicyInputStream() throws IOException {
        return resourceLoader.getResource(defaultPolicyPath).getInputStream();
    }
}
