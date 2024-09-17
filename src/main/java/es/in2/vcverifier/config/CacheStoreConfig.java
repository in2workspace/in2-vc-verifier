package es.in2.vcverifier.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {
    @Bean
    public CacheStore<String> cacheStoreDefault() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public Set<String> jtiCache() {
        return new HashSet<>();
    }
}