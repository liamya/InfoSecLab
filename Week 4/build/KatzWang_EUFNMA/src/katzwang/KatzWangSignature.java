package katzwang;
/**
 * A Katz Wang DDH-based signature
 * @param E the class for the exponents used in the signature
 */
public class KatzWangSignature<E> {
    /**
     * response part of signature
     */
    public final E s;
    /**
     * challenge part of signature, i.e. for a valid signature this would be c = H(PK, g^sy_1^-c, h^sy_2^-c,m)
     */
    public final E c;
    
    public KatzWangSignature(E c, E s) {
        this.s = s;
        this.c = c;
    }
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((c == null) ? 0 : c.hashCode());
        result = prime * result + ((s == null) ? 0 : s.hashCode());
        return result;
    }
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KatzWangSignature other = (KatzWangSignature) obj;
        if (c == null) {
            if (other.c != null)
                return false;
        } else if (!c.equals(other.c))
            return false;
        if (s == null) {
            if (other.s != null)
                return false;
        } else if (!s.equals(other.s))
            return false;
        return true;
    }

    
    
}
