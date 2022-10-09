package algebra;

import java.math.BigInteger;

/**
 * A SimplePolynomial represents univariate polynomials over the integers or
 * over Z/nZ.
 * 
 * This class offers basic methods for arithmetic operations in the ring of
 * polynomials (addition, subtraction, multiplication, division etc.).
 * Coefficients of this class are represented by BigIntegers.
 * 
 * Instances of this class are immutable.
 */
public class SimplePolynomial implements Comparable<SimplePolynomial> {
    /**
     * The characteristic of the ring of this polynomial.
     * May be zero (in this case, its ring is Z[X]).
     */
    public final BigInteger modulus;
    /**
     * The coefficients of this polynomial.
     * Formally, this polynomial is given as:
     * coefficients[0] + coefficients[1] * X + ... + coefficients[degree] * X^degree
     * 
     * Note, that the zero polynomial has zero coefficients.
     */
    private final BigInteger[] coefficients;
    /**
     * The degree of this polynomial.
     * It is guaranteed that coefficients[degree] is not zero (modulo modulus).
     * 
     * The degree of the zero polynomial is -1.
     */
    public final int degree;

    /**
     * Generates the zero polynomial.
     * 
     * @param modulus modulus of the ring, in which this polynomial lives.
     */
    public SimplePolynomial(BigInteger modulus) {
        this(modulus, new BigInteger[0]);
    }

    /**
     * Generates a polynomial with the given coefficients.
     * 
     * @param modulus      modulus of the ring, in which this polynomial lives.
     * @param coefficients coefficients of the polynomial in increasing order.
     *                     I.e., coefficients[0] + coefficients[1] * X + ... +
     *                     coefficients[degree] * X^degree.
     *                     The coefficients will be reduced modulo modulus and
     *                     trailing zero coefficients will be trimmed.
     */
    public SimplePolynomial(BigInteger modulus, int... coefficients) {
        this(modulus, convert(coefficients));
    }

    private static BigInteger[] convert(int[] coefficients) {
        BigInteger[] coeffs = new BigInteger[coefficients.length];
        for (int i = 0; i < coeffs.length; i++)
            coeffs[i] = BigInteger.valueOf(coefficients[i]);
        return coeffs;
    }

    /**
     * Generates a polynomial with the given coefficients.
     * 
     * @param modulus      modulus of the ring, in which this polynomial lives.
     * @param coefficients coefficients of the polynomial in increasing order.
     *                     I.e., coefficients[0] + coefficients[1] * X + ... +
     *                     coefficients[degree] * X^degree.
     *                     The coefficients will be reduced modulo modulus and
     *                     trailing zero coefficients will be trimmed.
     */
    public SimplePolynomial(BigInteger modulus, BigInteger... coefficients) {
        this.modulus = modulus;
        int degree = coefficients.length - 1;

        if (modulus.signum() < 0)
            throw new IllegalArgumentException("modulus must be zero or a positive number!");

        while (degree >= 0 && reduce(coefficients[degree]).signum() == 0)
            degree--;
        this.degree = degree;
        this.coefficients = new BigInteger[degree + 1];
        for (int i = 0; i <= degree; i++) {
            this.coefficients[i] = reduce(coefficients[i]);
        }
    }

    /**
     * Returns number, if modulus == 0, and number mod modulus, otherwise.
     */
    private BigInteger reduce(BigInteger number) {
        if (modulus.signum() == 0)
            return number;
        else
            return number.mod(modulus);
    }

    /**
     * Returns the i-th coefficient of this polynomial.
     * 
     * @param i a number in 0, ..., degree.
     * @return c_i where this polynomial is given by c_0 + c_1 * X + c_2 * X^2 + ...
     *         + c_degree * X^degree.
     */
    public BigInteger get(int i) {
        if (i < 0)
            throw new IllegalArgumentException("i may not be negative!");
        if (i > degree)
            throw new IllegalArgumentException("i was higher that the degree of this polynomial!");
        return coefficients[i];
    }

    /**
     * Returns an array of n Zeros.
     */
    private static BigInteger[] zeros(int n) {
        var array = new BigInteger[n];
        for (int i = 0; i < array.length; i++)
            array[i] = BigInteger.ZERO;
        return array;
    }

    /**
     * Returns a new polynomial that equals the sum of this and other.
     * 
     * @param other a polynomial that you want to add to this. Must have the same
     *              modulus as this one.
     * @return a new polynomial that equals the sum of this and other.
     */
    public SimplePolynomial add(SimplePolynomial other) {
        if (!this.modulus.equals(other.modulus))
            throw new IllegalArgumentException("Both polynomials need to have the same modulus!");

        BigInteger[] coeffs = zeros(Math.max(this.degree, other.degree) + 1);
        for (int i = 0; i < this.coefficients.length; i++)
            coeffs[i] = this.coefficients[i];
        for (int i = 0; i < other.coefficients.length; i++)
            coeffs[i] = coeffs[i].add(other.coefficients[i]);

        return new SimplePolynomial(modulus, coeffs);
    }

    /**
     * Returns a new polynomial that equals this - other.
     * 
     * @param other a polynomial that you want to subtract from this. Must have the
     *              same
     *              modulus as this one.
     * @return a new polynomial that equals this - other.
     */
    public SimplePolynomial subtract(SimplePolynomial other) {
        if (!this.modulus.equals(other.modulus))
            throw new IllegalArgumentException("Both polynomials need to have the same modulus!");

        BigInteger[] coeffs = zeros(Math.max(this.degree, other.degree) + 1);
        for (int i = 0; i < this.coefficients.length; i++)
            coeffs[i] = this.coefficients[i];
        for (int i = 0; i < other.coefficients.length; i++)
            coeffs[i] = coeffs[i].subtract(other.coefficients[i]);

        return new SimplePolynomial(modulus, coeffs);
    }

    /**
     * Returns a new polynomial that equals this * other.
     * 
     * @param other a polynomial that you want to multiply with this. Must have the
     *              same
     *              modulus as this one.
     * @return the product of this and other
     */
    public SimplePolynomial multiply(SimplePolynomial other) {
        if (!this.modulus.equals(other.modulus))
            throw new IllegalArgumentException("Both polynomials need to have the same modulus!");

        BigInteger[] coeffs = zeros(this.degree + other.degree + 1);
        for (int i = 0; i < this.coefficients.length; i++)
            for (int j = 0; j < other.coefficients.length; j++)
                coeffs[i + j] = reduce(coeffs[i + j].add(this.coefficients[i].multiply(other.coefficients[j])));

        return new SimplePolynomial(modulus, coeffs);
    }

    /**
     * Returns a new polynomial that equals number * this.
     * 
     * @param other a number that you want to multiply with this.
     * @return the product of this and number.
     */
    public SimplePolynomial multiply(BigInteger number) {
        BigInteger[] coeffs = new BigInteger[this.degree + 1];
        for (int i = 0; i < this.coefficients.length; i++)
            coeffs[i] = this.coefficients[i].multiply(number);

        return new SimplePolynomial(modulus, coeffs);
    }

    /**
     * Returns the leading term of this polynomial.
     * 
     * @return the coefficient of the highest degree monomial of this polynomial.
     *         If this polynomial is zero, zero will be returned.
     */
    public BigInteger lead() {
        if (degree == -1)
            return BigInteger.ZERO;
        return coefficients[degree];
    }

    /**
     * Returns the polynomial coefficient * X^degree.
     */
    private SimplePolynomial getMonomial(BigInteger modulus, int degree, BigInteger coefficient) {
        var cs = zeros(degree + 1);
        cs[degree] = coefficient;
        return new SimplePolynomial(modulus, cs);
    }

    /**
     * Divides this by the given divisor.
     * This method computes q and r s.t. this = q * divisor + r
     * and deg(r) < deg(divisor) and returns q.
     * 
     * This method only works for positive modulus!
     * 
     * @param divisor may not be zero.
     * @return the quotient this/divisor (without remainder).
     */
    public SimplePolynomial div(SimplePolynomial divisor) {
        if (modulus.signum() == 0)
            throw new IllegalArgumentException("Division is only supported for prime modulus!");
        if (!this.modulus.equals(divisor.modulus))
            throw new IllegalArgumentException("Both polynomials need to have the same modulus!");
        if (divisor.degree < 0)
            throw new IllegalArgumentException("divisor is zero!");

        var result = new SimplePolynomial(modulus);

        var c = divisor.lead().negate().modInverse(divisor.modulus);
        var remainder = this;
        while (remainder.degree >= divisor.degree) {
            int d = remainder.degree - divisor.degree;
            var a = remainder.lead().multiply(c);

            var off = getMonomial(modulus, d, a);
            remainder = remainder.add(off.multiply(divisor));
            result = result.subtract(off);
        }
        return result;
    }

    /**
     * Evaluates this polynomial on the given input.
     * 
     * @param input a value on which you want to evaluate this polynomial.
     * @return this(input).
     */
    public BigInteger eval(BigInteger input) {
        var result = BigInteger.ZERO;
        var power = BigInteger.ONE;
        for (int i = 0; i < coefficients.length; i++) {
            result = result.add(power.multiply(coefficients[i]));
            power = reduce(power.multiply(input));
        }
        return reduce(result);
    }

    /**
     * Returns the polynomial this(X - offset).
     * 
     * @param offset by what number do you want to shift the input of this
     *               polynomial.
     * @return a polynomial p of the same degree s.t. we have for all x
     *         this(x + offset) = p(x).
     */
    public SimplePolynomial shift(int offset) {
        return this.shift(BigInteger.valueOf(offset));
    }

    /**
     * Returns the polynomial this(X - offset).
     * 
     * @param offset by what number do you want to shift the input of this
     *               polynomial.
     * @return a polynomial p of the same degree s.t. we have for all x
     *         this(x + offset) = p(x).
     */
    public SimplePolynomial shift(BigInteger offset) {
        var result = new SimplePolynomial(modulus);
        var power = new SimplePolynomial(modulus, 1);
        var factor = new SimplePolynomial(modulus, offset.negate(), BigInteger.ONE);
        for (int i = 0; i < coefficients.length; i++) {
            result = result.add(power.multiply(coefficients[i]));
            power = power.multiply(factor);
        }
        return result;
    }

    /**
     * Returns iff this polynomial is zero.
     * 
     * @return true if this is the zero polynomial.
     */
    public boolean isZero() {
        return degree == -1;
    }

    /**
     * Returns true iff this polynomial is one.
     * 
     * @return true iff this is multiplicative unity of its polynomial ring.
     */
    public boolean isOne() {
        return degree == 0 && coefficients[0].equals(BigInteger.ONE);
    }

    /**
     * Returns true iff this polynomial is constant.
     * 
     * @return true iff the degree of this polynomial is at most 0.
     */
    public boolean isConstant() {
        return degree <= 0;
    }

    /**
     * Compares this polynomial with other.
     * 
     * @param other Polynomial to be compared with. Can have other modulus.
     * @return Returns 0 if both polynomials are equal in each regard.
     *         If both polynomials have different moduli, returns +1/-1 if this
     *         polynomial's modulus is larger/smaller than other's.
     *         Otherwise, if both polynomials have different degrees, returns +1/-1
     *         if this polynomial's degree is larger/smaller than other's.
     *         Otherwise, returns +1 / - 1 if there is an i in [0, degree] s.t.
     *         this.coefficients[i] is larger / smaller than other.coefficients[i]
     *         (compared over the integers) and we have this.coefficients[j] ==
     *         other.coefficients[j] for all j in [i + 1, degree].
     */
    @Override
    public int compareTo(SimplePolynomial other) {
        int m = this.modulus.compareTo(other.modulus);
        if (m != 0)
            return m;
        if (this.degree > other.degree)
            return 1;
        if (this.degree < other.degree)
            return -1;
        for (int i = degree; i >= 0; i--) {
            int c = this.coefficients[i].compareTo(other.coefficients[i]);
            if (c != 0)
                return c;
        }
        return 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null)
            return false;
        if (!(obj instanceof SimplePolynomial))
            return false;
        return this.compareTo((SimplePolynomial) obj) == 0;
    }

    @Override
    public String toString() {
        if (isZero())
            return "0";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i <= degree; i++) {
            if (coefficients[i].signum() < 0) {
                if (sb.length() > 0)
                    sb.append(" ");
            } else if (coefficients[i].signum() > 0) {
                if (sb.length() > 0)
                    sb.append(" + ");
            } else
                continue;
            sb.append(coefficients[i]);
            if (i > 0)
                sb.append(" X^" + i);
        }
        return sb.toString();
    }
}
