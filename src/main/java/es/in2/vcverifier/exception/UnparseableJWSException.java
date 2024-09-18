package es.in2.vcverifier.exception;

public class UnparseableJWSException extends RuntimeException {
    public static final String DEFAULT_EXCEPTION_MESSAGE = "Error reading data to verify";

    public UnparseableJWSException(String message, Exception e) {
        super(message, e);
    }
}
