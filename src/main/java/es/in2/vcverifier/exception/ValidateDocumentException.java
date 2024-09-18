package es.in2.vcverifier.exception;

public class ValidateDocumentException extends RuntimeException {
    public static final String DEFAULT_EXCEPTION_MESSAGE = "Error loading keystore";

    public ValidateDocumentException(String message, Exception e) {
        super(message, e);
    }
}

