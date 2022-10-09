package utils;
/**
 * a pair of two things
 * @param A the type of the first element in the pair
 * @param B the type of the second element in the pair
 */
public class Pair<A, B> {
    /**
     * first element of the pair
     */
    public final A first;
    /**
     * second element of the pair
     */
    public final B second;

    public Pair(A a, B b) {
        this.first = a;
        this.second = b;
    }
    @Override
    public boolean equals(Object _other) {
        if (_other == null) { return false;}
        Pair<Object,Object> other;
        if (!(_other instanceof Pair<?,?>)) {
            return false;
        } else {other  = (Pair<Object, Object>) _other;}
        if (this.first == null) {
            if (other.first == null)
                return true;
            else
                return false;

        } else if (this.second == null) {
            if (other.first == null)
                return true;
            else
                return false;
        }

        return this.first.equals(other.first) && this.second.equals(other.second);

    }

    @Override
    public int hashCode() {
        int hasha;
        int hashb;
        if (first == null) {
            hasha = 0;
        } else {
            hasha = first.hashCode();
        }
        if (second == null) {
            hashb = 0;
        } else {
            hashb = second.hashCode();
        }
        return hasha + hashb;
    }

    @Override
    public String toString() {
        return "Pair: A " + first.toString() + " B: " + second.toString();
    }

}
