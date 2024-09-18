package es.in2.vcverifier.exception;

public class WrongDocumentFormatException extends RuntimeException {
    public static final String DEFAULT_EXCEPTION_MESSAGE = "Error loading keystore";

    public WrongDocumentFormatException(String message, Exception e) {
        super(message, e);
    }
}
