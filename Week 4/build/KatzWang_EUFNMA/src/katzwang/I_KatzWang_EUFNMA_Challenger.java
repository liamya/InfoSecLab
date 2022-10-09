package katzwang;


import basics.IChallenger;

public interface I_KatzWang_EUFNMA_Challenger<G, E> extends IChallenger {
    /**
     * outputs the challenge public key.
     * @return a public key of the Katz Wang scheme
     */
    public KatzWangPK<G> getChallenge();
    /**
     * a random oracle hash function implementation that maps from G x G x M (where M is the space of Strings) to Z_p
     * @param comm1 the first group element input to the hash function
     * @param comm2 the second group element input to the hash function
     * @param message the message
     * @return a hash value from Z_p
     */
    public E hash(G comm1, G comm2, String message);
    
}
