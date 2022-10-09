package rsapkcs;

import java.math.BigInteger;

import basics.IChallenger;

public interface I_RSAPKCS_OWCL_Challenger extends IChallenger {
    /**
     * @return a public key for the RSA-PKCS scheme.
     */
    public RSAPKCS_PK getPk();

    /**
     * @return the challenge ciphertext in PKCS#1 format
     */
    public BigInteger getChallenge();

    /**
     * @return the maximal length of a plaintext in bytes
     */
    public int getPlainTextLength();

    /**
     * @param ciphertext which is checked for PKCS conformity
     * @return true iff ciphertext is conforming according to the definition in the task description
     */
    public boolean isPKCSConforming(BigInteger ciphertext) throws Exception;
}
