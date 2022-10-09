package utils;

import java.math.BigInteger;
import java.util.Random;

public class NumberUtils {
    /**
     * 
     * Returns a random Java BigInteger between 0 and max - 1.
     * 
     * @param RNG a random number generator whose randomness shall be used.
     * @param max An exclusive upper bound for the random number which shall be
     *            sampled. This argument must be positive!
     * @return returns a BigInteger which is sampled from the uniform distribution
     *         of the set {0, ..., max - 1}.
     */
    public static BigInteger getRandomBigInteger(Random RNG, BigInteger max) {
        if (max == null)
            return null;
        if (max.signum() <= 0)
            return null;
        var next = new BigInteger(max.bitLength(), RNG);
        while (next.compareTo(max) >= 0)
            next = new BigInteger(max.bitLength(), RNG);
        return next;
    }

    /**
     * Returns the logarithm of number to the base 2, rounded up.
     * I.e. ceil( log2 ( number ) ).
     * Only works for positive numbers, i.e. > 0!
     * 
     * @param number the number of which you want to compute the logarithm.
     * @return the ceiling of the logarithm of number.
     * @throws IllegalArgumentException will be thrown if number is zero or
     *                                  negative.
     */
    public static int getCeilLog(BigInteger number) throws IllegalArgumentException {
        if (number.signum() < 1)
            throw new IllegalArgumentException("number must be positive!");
        return number.subtract(BigInteger.ONE).bitLength();
    }

    /**
     * Returns the quotient of two numbers, rounded up.
     * I.e. ceil( numerator / denominator ).
     * 
     * @param numerator   the numerator
     * @param denominator the denominator
     * @return the quotient of the two arguments rounded up
     */
    public static BigInteger ceilDivide(BigInteger numerator, BigInteger denominator) {
        var r = numerator.divideAndRemainder(denominator);
        if (r[1].compareTo(BigInteger.ZERO) == 0) {
            return r[0];
        } else {
            return r[0].add(BigInteger.ONE);
        }
    }
}
