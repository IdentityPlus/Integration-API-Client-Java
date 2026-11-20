package identity.plus.api.json;

import java.util.Arrays;
import java.util.Objects;

import identity.plus.api.communication.Outcome;

/** Helpers for records that carry secret material: defensive copies, equality, redacted printing. */
public final class Secrets {
    private Secrets() {}

    public static byte[] copy(byte[] b)     { return b == null ? null : b.clone(); }
    public static String size(byte[] b)     { return b == null ? "null" : b.length + " bytes"; }
    public static String redacted(Object o) { return o == null ? "null" : "<redacted>"; }

    /** Equality and hash over the four credential fields shared by the identity records. */
    public static boolean same(byte[] p12_a, String pw_a, byte[] cert_a, byte[] key_a,
                        byte[] p12_b, String pw_b, byte[] cert_b, byte[] key_b) {
        return Objects.equals(pw_a, pw_b)
            && Arrays.equals(p12_a, p12_b)
            && Arrays.equals(cert_a, cert_b)
            && Arrays.equals(key_a, key_b);
    }

    public static int hash(byte[] p12, String password, byte[] certificate, byte[] private_key) {
        return Objects.hash(password, Arrays.hashCode(p12), Arrays.hashCode(certificate), Arrays.hashCode(private_key));
    }

    public static String describe(String type, Outcome outcome, byte[] p12, String password, byte[] certificate, byte[] private_key) {
        return type + "[outcome=" + outcome
             + ", certificate=" + size(certificate)
             + ", p12=" + redacted(p12)
             + ", private_key=" + redacted(private_key)
             + ", password=" + redacted(password) + "]";
    }
}