package es.in2.vcverifier.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@RequiredArgsConstructor
public class SignatureEvidence {
    private String signatureType;

    private String indication;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String subIndication;
}
