package cdh_quadratic;

import cdh.I_CDH_Adversary;

/**
 * A quadratic adversary is a CDH adversary with a twist:
 * when given a CDH challenge (g, g^X, g^Y), this adversary will return the
 * group element g^(aXY + bX + cY + d)
 * for fixed, but randomly chosen values a, b, c, d \in Zp.
 * 
 * The adversary is consistent with regard to a,b,c,d. I.e., when queried with
 * the challenges
 * (g, g^X1, g^Y1), (g, g^X2, g^Y2), ..., (g, g^Xn, g^Yn),
 * this adversary will reply with g^(aX1Y1 + bX1 + cY1 + d),
 * g^(aX2Y2 + bX2 + cY2 + d), ..., g^(aXnYn + bXn + cYn + d).
 * 
 * It is guaranteed that a is never zero.
 */
public interface I_Quadratic_Adversary<G> extends I_CDH_Adversary<G> {
}
