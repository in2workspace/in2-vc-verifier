package es.in2.vcverifier.model;


import lombok.Builder;

import java.util.List;

@Builder
public record ValidationResponse (
        String policyName,

        int validSignatureCount,

        int signatureCount,

        List<SignatureEvidence> signatureEvidence
){
}