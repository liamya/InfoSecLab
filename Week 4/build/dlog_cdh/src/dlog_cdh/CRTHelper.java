package dlog_cdh;

import java.math.BigInteger;

/**
 * This class provides a method for composing back numbers according to the
 * Chinese Remainder Theorem.
 */
public final class CRTHelper {
    /**
     * Returns a number b in {0, ..., p - 1} s.t. for all i
     * b mod moduli[i] == values[i]
     * where p = moduli[0] * ... * moduli[n - 1].
     * 
     * @param values some values.
     * @param moduli any numbers that are pairwise COPRIME.
     * @return a number b in {0, ..., p - 1} s.t. for all i
     *         b mod moduli[i] == values[i]
     *         where p = moduli[0] * ... * moduli[n - 1].
     */
    public static BigInteger crtCompose(int[] values, int[] moduli) {
        BigInteger p = BigInteger.valueOf(moduli[0]);
        BigInteger result = BigInteger.valueOf(values[0]);
        result = result.mod(p);
        for (int i = 1; i < moduli.length; i++) {
            var q = BigInteger.valueOf(moduli[i]);
            var k = BigInteger.valueOf(values[i]);
            k = k.mod(q);
            k = k.subtract(result);
            k = k.multiply(p.modInverse(q));
            result = result.add(p.multiply(k));
            p = p.multiply(q);
        }
        return result.mod(p);
    }
}
