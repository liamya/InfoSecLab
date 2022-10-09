package dy05;

import genericGroups.IGroupElement;

public class DY05_PK {
    /**
     * A generator of the group.
     */
    public final IGroupElement generator;
    /**
     * A commitment to the secret key. I.e. a group element of the form g^s (where s
     * is the secret key of the VRF).
     */
    public final IGroupElement gS;

    public DY05_PK(IGroupElement generator, IGroupElement gS) {
        this.generator = generator;
        this.gS = gS;
    }
}