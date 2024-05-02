package orishop.util;

import java.security.SecureRandom;
import java.math.BigInteger;

public class CSRFTokenGenerator {

    private static final int NUM_BYTES = 16; // Number of bytes for the token

    public static String generateCSRFToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[NUM_BYTES];
        random.nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16);
    }
}
