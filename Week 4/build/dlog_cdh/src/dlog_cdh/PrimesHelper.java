package dlog_cdh;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * A class that provides four prime numbers p >= 2^80 together with special
 * information
 * like prime factor decompositions of p - 1 and generators of the
 * multiplicative group Zp^*.
 * 
 * Each prime number p outputted by getRandomPrime is bigger than 2^80 and has
 * the property that p - 1 has a prime factor decomposition into small factors
 * (<= 71) where each factor occurs at most once.
 * 
 * The information outputted by this class is precomputed and hardcoded into its source code.
 */
public final class PrimesHelper {

    private static BigInteger[] primes = new BigInteger[] {
            new BigInteger("1384468561108434146321131"),
            new BigInteger("24258296962030389607278931"),
            new BigInteger("3901684126760132594177731"),
            new BigInteger("2415328268946748748776691"),
    };
    private static int[][] phiDecompositions = new int[][] {
            { 2, 3, 5, 7, 11, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 61, 67, 71, },
            { 2, 3, 5, 7, 11, 13, 17, 19, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, },
            { 2, 3, 5, 7, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, },
            { 2, 5, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, },
    };
    private static BigInteger[] generators = new BigInteger[] {
            new BigInteger("3"),
            new BigInteger("3"),
            new BigInteger("10"),
            new BigInteger("2"),
    };

    /**
     * Returns one of the four prime numbers known to this class.
     * 
     * @param i A number in {0, 1, 2, 3}.
     * @return a prime number p s.t. p >= 2^80 and p - 1 has a decomposition into
     *         primes <= 71 s.t. each prime factor occurs at most once.
     */
    public static BigInteger getPrime(int i) {
        return primes[i];
    }

    /**
     * Returns randomly one of the four prime numbers known to this class.
     * 
     * @param random An RNG that determines which prime number shall be returned.
     * @return a prime number p s.t. p >= 2^80 and p - 1 has a decomposition into
     *         primes <= 71 s.t. each prime factor occurs at most once.
     */
    public static BigInteger getRandomPrime(Random random) {
        int i = random.nextInt(primes.length);
        return getPrime(i);
    }

    /**
     * Returns a prime factor decomposition of phi(prime) = prime - 1.
     * If prime is not one of the prime numbers issued by getPrime, this
     * method will throw an exception.
     * 
     * @param prime a prime number known to this method i.e. outputted by
     *              getPrime.
     * @return an array of integers s.t. prime is the product of each element of
     *         this array.
     *         The elements of the array are sorted from smallest to largest number.
     *         Each element is a prime number <= 71.
     */
    public static int[] getDecompositionOfPhi(BigInteger prime) {
        for (int i = 0; i < primes.length; i++)
            if (prime.equals(primes[i]))
                return phiDecompositions[i];
        throw new IllegalArgumentException("The given prime number is unknown to me!");
    }

    /**
     * Returns a generator of the multiplicative group of Zp.
     * If prime is not one of the prime numbers issued by getPrime, this
     * method will throw an exception.
     * 
     * @param prime a prime number known to this method i.e. outputted by
     *              getPrime.
     * @return a small number z in {1, ..., p - 1} s.t. z multiplicatively generates
     *         Zp^*. I.e. we have the equality of unordered sets
     *         { 1, z, z^2 mod p, z^3 mod p, ..., z^{p-2} mod p } == { 1, 2, ..., p
     *         - 1 }.
     */
    public static BigInteger getGenerator(BigInteger prime) {
        for (int i = 0; i < primes.length; i++)
            if (prime.equals(primes[i]))
                return generators[i];
        throw new IllegalArgumentException("The given prime number is unknown to me!");
    }

    /**
     * Computes all probable primes p of the form p = 1 + 2^b1 * 3^b2 * ... * 71^b20
     * for b1, ..., b20 in {0,1} that are bigger than 2^80 and outputs them together
     * with factorizations of p - 1 and generators of their multiplicative group.
     * 
     * @param args irrelevant.
     */
    public static void main(String[] args) {
        // The first 20 prime numbers
        BigInteger[] primes = {
                new BigInteger("2"),
                new BigInteger("3"),
                new BigInteger("5"),
                new BigInteger("7"),
                new BigInteger("11"),
                new BigInteger("13"),
                new BigInteger("17"),
                new BigInteger("19"),
                new BigInteger("23"),
                new BigInteger("29"),

                new BigInteger("31"),
                new BigInteger("37"),
                new BigInteger("41"),
                new BigInteger("43"),
                new BigInteger("47"),
                new BigInteger("53"),
                new BigInteger("59"),
                new BigInteger("61"),
                new BigInteger("67"),
                new BigInteger("71"),

                // new BigInteger("73"),
                // new BigInteger("79"),
                // new BigInteger("83"),
                // new BigInteger("89"),
                // new BigInteger("97"),
        };

        List<BigInteger> euclids = new ArrayList<BigInteger>();
        List<Integer> decomps = new ArrayList<Integer>();
        List<BigInteger> generators = new ArrayList<BigInteger>();

        var threshold = BigInteger.TWO.pow(80);

        for (int i = 0; i < 1 << primes.length; i++) {
            BigInteger prod = BigInteger.ONE;
            for (int j = 0; j < primes.length; j++)
                if ((i & (1 << j)) != 0)
                    prod = prod.multiply(primes[j]);
            prod = prod.add(BigInteger.ONE);
            if (prod.isProbablePrime(80) && prod.compareTo(threshold) > 0) {
                euclids.add(prod);
                decomps.add(i);
            }
        }

        for (int i = 0; i < euclids.size(); i++) {
            var p = euclids.get(i);
            boolean isGenerator = false;
            var g = BigInteger.TWO;
            while (!isGenerator) {
                isGenerator = true;
                int decomp = decomps.get(i);
                for (int j = 0; j < primes.length; j++)
                    if ((decomp & (1 << j)) != 0) {
                        var testOrder = p.divide(primes[j]);
                        var z = g.modPow(testOrder, p);
                        if (z.equals(BigInteger.ONE)) {
                            isGenerator = false;
                            g = g.add(BigInteger.ONE);
                            break;
                        }
                    }
            }
            generators.add(g);
        }

        System.out.println("new BigInteger[]{");
        for (int i = 0; i < euclids.size(); i++) {
            System.out.print("new BigInteger(\"");
            System.out.print(euclids.get(i));
            System.out.println("\"),");
        }
        System.out.println("};");
        System.out.println();
        System.out.println();

        System.out.println("new int[][]{");
        for (int i = 0; i < euclids.size(); i++) {
            System.out.print("{");

            int decomp = decomps.get(i);
            for (int j = 0; j < primes.length; j++)
                if ((decomp & (1 << j)) != 0)
                    System.out.print(primes[j] + ", ");

            System.out.println("},");
        }
        System.out.println("};");
        System.out.println();
        System.out.println();

        System.out.println("new BigInteger[]{");
        for (int i = 0; i < generators.size(); i++) {
            System.out.print("new BigInteger(\"");
            System.out.print(generators.get(i));
            System.out.println("\"),");
        }
        System.out.println("};");

    }
}
