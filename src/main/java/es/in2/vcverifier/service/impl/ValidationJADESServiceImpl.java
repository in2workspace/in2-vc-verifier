package es.in2.vcverifier.service.impl;

import es.in2.vcverifier.config.properties.ValidationPoliciesConfigProperties;
import es.in2.vcverifier.exception.UnparseableJWSException;
import es.in2.vcverifier.exception.ValidateDocumentException;
import es.in2.vcverifier.exception.WrongDocumentFormatException;
import es.in2.vcverifier.model.SignatureEvidence;
import es.in2.vcverifier.model.ValidationResponse;
import es.in2.vcverifier.service.ValidationJADESService;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.validation.*;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Component
@AllArgsConstructor
public class ValidationJADESServiceImpl implements ValidationJADESService {

    private final ValidationPoliciesConfigProperties validationPoliciesConfigProperties;
//    private final CertificateVerifier certificateVerifier;

    @Override
    public boolean validate(String signedObject) {
        SignedDocumentValidator documentValidator = getSignedDocumentValidator(signedObject);
        configureDocumentValidator(documentValidator);

        Reports reports;
        try {
            reports = documentValidator.validateDocument(validationPoliciesConfigProperties.getDefaultPolicyInputStream());
        } catch (Exception e) {
            throw new ValidateDocumentException(e.getMessage(), e);
        }

        ValidationResponse validationResponse = mapSimpleReportToValidationResponse(reports.getSimpleReport());

        // Verificar si todas las firmas en el reporte son válidas
        return validationResponse.validSignatureCount() == validationResponse.signatureCount();
    }


    private SignedDocumentValidator getSignedDocumentValidator(String signedData) {
        DSSDocument signedDocument = new InMemoryDocument(signedData.getBytes(StandardCharsets.UTF_8));

        try {
            return  SignedDocumentValidator.fromDocument(signedDocument);
        } catch (IllegalInputException e) {
            throw new UnparseableJWSException(e.getMessage(), e);
        } catch (UnsupportedOperationException e) {
            throw new WrongDocumentFormatException(e.getMessage(), e);
        }
    }

    private void configureDocumentValidator(SignedDocumentValidator documentValidator) {
        documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

        documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

        documentValidator.setIncludeSemantics(true);
    }

    private ValidationResponse mapSimpleReportToValidationResponse(SimpleReport simpleReport) {
        ValidationResponse.ValidationResponseBuilder validationResponse = ValidationResponse.builder()
                .validSignatureCount(simpleReport.getValidSignaturesCount())
                .signatureCount(simpleReport.getSignaturesCount())
                .policyName(simpleReport.getJaxbModel().getValidationPolicy().getPolicyName());


        List<SignatureEvidence> signatureEvidences =  new ArrayList<>();

        simpleReport.getJaxbModel().getSignatureOrTimestampOrEvidenceRecord()
                .forEach(xmlToken -> {
                    XmlSignature xmlSignature = (XmlSignature) xmlToken;
                    SignatureEvidence signatureEvidence =  new SignatureEvidence();

                    if (xmlSignature.getIndication() != null) {
                        signatureEvidence.setIndication(xmlSignature.getIndication().name());
                    }
                    if (xmlSignature.getSubIndication() != null) {
                        signatureEvidence.setIndication(xmlSignature.getSubIndication().name());
                    }

                    if (xmlSignature.getSignatureFormat() != null) {
                        signatureEvidence.setSignatureType(xmlSignature.getSignatureFormat().name());
                    }

                    signatureEvidences.add(signatureEvidence);
                });

        validationResponse.signatureEvidence(signatureEvidences);

        return validationResponse.build();
    }
}
