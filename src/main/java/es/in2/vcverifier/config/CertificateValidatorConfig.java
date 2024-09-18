package es.in2.vcverifier.config;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//@Configuration
//@Slf4j
//public class CertificateValidatorConfig {
//    private final CertificateConfig certificateConfig;
//    private final CommonCertificateVerifier commonCertificateVerifier;
//
//
//    public CertificateValidatorConfig(@Autowired CertificateConfig certificateConfig) {
//        this.certificateConfig = certificateConfig;
//        this.commonCertificateVerifier = new CommonCertificateVerifier();
//    }
//
//
//    @Bean
//    public CertificateVerifier certificateVerifier() {
//        CommonTrustedCertificateSource certificateSource = getCommonTrustedCertificateSource();
//
//        commonCertificateVerifier.addTrustedCertSources(certificateSource);
//        return commonCertificateVerifier;
//    }
//
//    private CommonTrustedCertificateSource getCommonTrustedCertificateSource() {
//        CertificateToken certificateToken = DSSUtils.loadCertificate(certificateConfig.getCertificate());
//        CommonTrustedCertificateSource certificateSource = new CommonTrustedCertificateSource();
//        certificateSource.addCertificate(certificateToken);
//
//        return certificateSource;
//    }
//
//
//}
