package rsapkcs;

import java.math.BigInteger;
import java.util.Random;

import utils.Triple;
import static utils.NumberUtils.getRandomBigInteger;

/**
 * The public key of the RSA-PKCS encryption scheme.
 */
public class RSAPKCS_PK {
    /**
     * The RSA modulus which is used by the RSA scheme.
     */
    public final BigInteger N;
    /**
     * ToDo: JavaDoc
     */
    public final BigInteger exponent;

    public RSAPKCS_PK(BigInteger N, BigInteger exponent) {
        this.N = N;
        this.exponent = exponent;
    }

    /**
     * Generates new RSA Public Key.
     * Samples probable primes p and q of the given bitlength and sets N = p * q.
     * Computes e in {0, ..., (p-1)(q-1) - 1} s.t. gcd(e, (p-1)(q-1)) = 1 and
     * returns the public key (N,e) together with the primes p and q.
     * 
     * @param rnd       the randomness used to sample p, q and e.
     * @param bitLength the length of p and q.
     * @return a Triple that contains the Public Key (N,e) and the secret primes p
     *         and q.
     */
    public static Triple<RSAPKCS_PK, BigInteger, BigInteger> GenerateRsaPkWithTrapdoor(Random rnd, int bitLength) {
        var p = BigInteger.probablePrime(bitLength, rnd);
        var q = BigInteger.probablePrime(bitLength, rnd);
        var N = p.multiply(q);
        var phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        var e = getRandomBigInteger(rnd, phi);
        while (!phi.gcd(e).equals(BigInteger.ONE))
            e = getRandomBigInteger(rnd, phi);

        RSAPKCS_PK pk = new RSAPKCS_PK(N, e);
        return new Triple<RSAPKCS_PK, BigInteger, BigInteger>(pk, p, q);
    }
}