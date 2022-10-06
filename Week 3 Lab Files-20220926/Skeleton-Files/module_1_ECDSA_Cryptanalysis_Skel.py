import math
import random
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def egcd(a, b):
    # Implement the Euclidean algorithm for gcd computation
    # using same code from previous lab, TODO: ask TA if thats ok
    # Update: he said its ok!
    if a == 0:
        return b, 0, 1
    else:
        g,y,x = egcd(b % a, a)
        return g, x - (b // a) * y, y
    
def mod_inv(a, p):
    # Implement a function to compute the inverse of a modulo p
    # Hint: Use the gcd algorithm implemented above
    if a < 1:
        return p-mod_inv(-a,p)
    g,x,y = egcd(a,p)

    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

def check_x(x, Q):
    """ Given a guess for the secret key x and a public key Q = [x]P,
        checks if the guess is correct.

        :params x:  secret key, as an int
        :params Q:  public key, as a tuple of two ints (Q_x, Q_y)
    """
    x = int(x)
    if x <= 0:
        return False
    Q_x, Q_y = Q
    sk = ec.derive_private_key(x, ec.SECP256R1())
    pk = sk.public_key()
    xP = pk.public_numbers()
    return xP.x == Q_x and xP.y == Q_y

def recover_x_known_nonce(k, h, r, s, q):
    # Implement the "known nonce" cryptanalytic attack on ECDSA
    # The function is given the nonce k, (h, r, s) and the base point order q
    # The function should compute and return the secret signing key x
    x = (mod_inv(r,q) * (k*s - h)) % q
    return x

def recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA
    # The function is given the (hashed-message, signature) pairs (h_1, r_1, s_1) and (h_2, r_2, s_2) generated using the same nonce
    # The function should compute and return the secret signing key x
    x = ((h_1*s_2 - h_2 * s_1) * mod_inv((r_2*s_1 - r_1*s_2),q)) % q
    return x

def bit_list_to_Int(list_k):
    a = 0
    for bit in list_k:
        a = (a << 1) | bit

    return a

def MSB_to_Padded_Int(N, L, list_k_MSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L most significant bits of the nonce k 
    # The function should return a.2^{N - L} + 2^{N -L -1}
    a = bit_list_to_Int(list_k_MSB)

    res = a * 2**(N-L) + 2**(N-L-1)
    return res



def LSB_to_Int(list_k_LSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L least significant bits of the nonce k 
    # The function should return a ??? TODO
    return bit_list_to_Int(list_k_LSB)

def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up a single instance for the hidden number problem (HNP)
    # The function is given a list of the L most significant bts of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return (t, u) computed as described in the lectures
    # In the case of EC-Schnorr, r may be set to h
    if givenbits == "msbs" and algorithm == "ecdsa": 
        t = (r * mod_inv(s,q)) % q
        z = (h*mod_inv(s,q)) % q

        u = (MSB_to_Padded_Int(N, L, list_k_MSB) - z) 
        return (t,u)
    elif givenbits == "lsbs" and algorithm == "ecdsa":
        # rearranged equation in (1) for t, u
        a_s = LSB_to_Int(list_k_MSB)
        t = mod_inv(2**L, q) * r * mod_inv(s, q) % q
        u = a_s * mod_inv(2**L, q) - h*mod_inv(s, q)*mod_inv(2**L, q)
        return (t,u)
    elif givenbits == "msbs" and algorithm == "ecschnorr":
        # same like in ecdsa, formulate equation in form hx = k - s + e where k = MSB padded
        t = h % q
        u = (MSB_to_Padded_Int(N, L, list_k_MSB) - s) 
        return (t,u)
    elif givenbits == "lsbs" and algorithm == "ecschnorr":
        # k=e*2^L + â
        # rearrange equation like in ecdsa 
        t = (mod_inv(2**L, q) * h) % q
        a_s = LSB_to_Int(list_k_MSB)
        u = (a_s * mod_inv(2**L, q)) - (s * mod_inv(2**L, q))
        return (t,u)



def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up n = num_Samples many instances for the hidden number problem (HNP)
    # For each instance, the function is given a list the L most significant bits of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return a list of t values and a list of u values computed as described in the lectures
    # Hint: Use the function you implemented above to set up the t and u values for each instance
    # In the case of EC-Schnorr, list_r may be set to list_h
    t = []
    u = []

    for i in range(num_Samples):
        (t_s, u_s) = setup_hnp_single_sample(N, L, listoflists_k_MSB[i], list_h[i], list_r[i], list_s[i], q, givenbits, algorithm)
        t.append(t_s)
        u.append(u_s)

    return (t, u)

def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    # Implement a function that takes as input an instance of HNP and converts it into an instance of the closest vector problem (CVP)
    # The function is given as input a list of t values, a list of u values and the base point order q
    # The function should return the CVP basis matrix B (to be implemented as a nested list) and the CVP target vector u (to be implemented as a list)
    # NOTE: The basis matrix B and the CVP target vector u should be scaled appropriately. Refer lecture slides and lab sheet for more details 
    B_CVP = []
    u_CVP = []

    # scaling each entry in B_CVP and u_CVP to make them integral
    scalar = 2**(L+1)

    # generate each row for q*scalar except for t row
    for i in range(num_Samples):
        entry = [0] * (num_Samples+1)
        entry[i] = q * scalar # q*scalar 0 0 0 ...
        B_CVP.append(entry)
    
    t_row = [(t_i * scalar) for t_i in list_t]
    # add 1/2(L+1) * 2(L+1) = 1 at the end
    t_row.append(1)
    B_CVP.append(t_row)

    u_CVP = [(u_i * scalar) for u_i in list_u]
    u_CVP.append(0)

    return (B_CVP, u_CVP)

def cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and converts it into an instance of the shortest vector problem (SVP)
    # Your function should use the Kannan embedding technique in the lecture slides
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should use the Kannan embedding technique to output the corresponding SVP basis matrix B' of apropriate dimensions.
    # The SVP basis matrix B' should again be implemented as a nested list
    B_SVP = []

    # TODO: FIND correct M
    M = 2**N
    for b_i in cvp_basis_B:
        b_i.append(0)
        B_SVP.append(b_i)

    cvp_list_u.append(M)

    B_SVP.append(cvp_list_u)
    return B_SVP


def solve_cvp(cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and solves it using in-built CVP-solver functions from the fpylll library
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should output the solution vector v (to be implemented as a list)
    # NOTE: The basis matrix B should be processed appropriately before being passes to the fpylll CVP-solver. See lab sheet for more details
    B_INT = IntegerMatrix.from_matrix(cvp_basis_B)
    B_INT_LLL = LLL.reduction(B_INT)
    v = CVP.closest_vector(B_INT_LLL, cvp_list_u)
    return v

def solve_svp(svp_basis_B):
    # Implement a function that takes as input an instance of SVP and solves it using in-built SVP-solver functions from the fpylll library
    # The function is given as input the SVP basis matrix B
    # The function should output a list of candidate vectors that may contain x as a coefficient
    # NOTE: Recall from the lecture and also from the exercise session that for ECDSA cryptanalysis based on partial nonces, you might want
    #       your function to include in the list of candidate vectors the *second* shortest vector (or even a later one). 
    # If required, figure out how to get the in-built SVP-solver functions from the fpylll library to return the second (or later) shortest vector
    
    # SVP requires Integer matrices as well
    B_INT = IntegerMatrix.from_matrix(svp_basis_B)
    #B_INT_LLL = LLL.reduction(svp_basis_B) ## lreduction not needed
    SVP.shortest_vector(B_INT) # According to https://github.com/fplll/fpylll/blob/master/docs/tutorial.rst
    # the shortest vector will be the same as A[0], assuming the second shortest is in A[1] => the i-th shortest in A[i]

    candidates = []
    # add all other candidate vectors (TODO)
    for row in B_INT:
        candidates.extend(row)

    return candidates



def recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    # TODO: givenbits and algorithm, set as msb und ecdsa per default
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    v_list = solve_cvp(cvp_basis_B, cvp_list_u)

    x = v_list[num_Samples] % q
    check = check_x(x, Q)
    if check == False:
       print("x coudlnt be recovered with cvp") 

    return x


def recover_x_partial_nonce_SVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    # The function should recover the secret signing key x from the output of the SVP solver and return it
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u)
    list_of_f_List = solve_svp(svp_basis_B)
    #print("length of u " + str(len(cvp_list_u)))
    #print("length of f " + str(len(list_of_f_List)))
    for f in list_of_f_List:
        for u in cvp_list_u:
            v_temp = (u-f) % q #according to exercise session
            if check_x(v_temp, Q):
                return v_temp

    # if we didnt find it yet, raise error
    raise ArithmeticError("Could not find the secret key out of all candidates")

# own testing code: TODO: comment before submit!!!!

"""
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

list_k_MSB = [1,0,0,1,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,0,1,1,1,0,0,0,1,0,1,0,0,0,0,1,1,1,1,1,0,1,0,1,0,0,1,1,0,0,1,1,1,0,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,1,1,0,0,1,0,0,1,1,1,0,1,0,1,1,1,0,1,1,1,1,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,]


h = 40486975916534473094362891519173006163331321367022210737537794685665135550740 
r = 2599887089937253404344006052124417371810051578242702686693991270543365335513 
s = 67330760927154883283279153345350424927695624629874283254165543075119816101003

N = 256
L = 128
l
(t,u) = setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa")
print("Testing WIlliam")
print(t)
print(u)

"""
"""
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
nestedList = [[1, 5]]
listoflists_k_MSB = [[1,0,0,0,0,1,0,0,0,0,0,0,1,0,0,1,0,0,1,1,1,0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,1,0,0,0,1,0,0,1,0,1,0,0,1,0,0,0,1,1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,1,0,0,1,1,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,0,0,0,1,0,1,1,1,0,0,0,0,1,0,1,0,0,1,1,0,0,0,0,1,1,1,0,1,1,0],
    [0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,1,0,0,1,1,0,0,1,0,0,0,0,1,1,0,0,0,0,1,0,0,0,1,1,0,0,0,0,0,0,0,0,1,1,1,0,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,1,0,0,1,0,1,1,1,0,0,0,0,0,1,1,1,1,1,1,0,0,1,0,0,1,0,0,0,1,1,0,1,1,0,1,0,1,0,0,1,1,0,1,1,1,1,1,0,0,0,0,1],
    [0,0,1,0,1,0,0,1,1,0,0,1,1,1,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,0,0,0,0,1,1,1,0,1,1,0,0,1,1,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,1,0,1,0,1,1,0,1,1,1,0,1,1,1,0,0,1,0,1,1,0,1,1,1,0,1,0,0,1,0,0,0,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,1,1,0,1,1,0,0,0,0,0,0,1],
    [0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,0,0,1,0,1,0,1,0,1,1,1,0,0,1,0,0,0,0,0,1,0,0,0,0,0,0,1,0,1,0,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,0,1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,1,1,0,1,0,1,1,1,0,1,0,1,1,0,1,0,1,0,0,1,1,1,1,1,1,1,1],
    [1,0,1,1,0,1,0,0,0,0,1,0,1,0,1,0,1,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,1,1,0,1,0,0,1,0,1,0,1,0,1,0,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,0,0,0,0,1,0,0,1,0,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,0,0,1,0,1,1,1,0,1,1,0,0,1,0,0,0,0,0,1,0,1,0,1,0,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,1]
]
list_h = [53587255018646766649366929761445263520588289974085164007791003592524300786856,92255010004322031700578648881153820869024394616292376385544824498220457132184,58718835091089030315016015430416018863376667084908539946409332614624098883365,21885430444463482694764703386347047586181776767178088530915395099876303569857,48222944448690727021865957867529225241421575091907648042040018560253341152938]
list_r = [86650740806009248676924548791021411531128002524761943337366852110719556852783,85571057469794218222664143406738900502813537611542662523671806135824277560790,73706532566196797600540175909728263111945346739811427832248273009783517562535,18542311856423834642035103399802628509185707655777332329168239974949541266375,69973303654333831673738387648804641189367623545062105314526463185158406522370]
list_s = [61673141712492429201103076862329639747659894086513332933883113480154908616994,72723065656456790043728442896109459240691424770121898239114476673586794127831,104798023990170995460147134633346919307495271521069945822399418971594476834879,12706672676671114233493645181512881611020875114875238286718605065948237298565,35162729381041556708199018195805592074241602412405847521869659206457930052664]

N = 256
L = 128
num_Samples = 5

#list_t:
#52577997114672223753883884838446907937044890369779123641851702741673933300393 46932074166957065539638659849940887951519230105319925555368992340377571557053 84820553559080745583027261353897864800947979801839692244239877715725580095196 46126924907659506248203645645615709268615240765699118030706873306761182621719 106527631476304177425961197417196630686327314523441020909831540061123479757974 

#list_u:
#-26598885662765484140686768782705345637611731714845993249000446855150630095422 -18343995083279027201836925768237081749568866408831159039518306880772015070530 -60507380181525666167703212102998312065962102451471468546639975941493460559927 -50291170320876502474766269797299965339493724137492678004407216833402748486257 16931683542557590285509095950598728801081622707341508999965512941943990704574 

(t_l,u_l) = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa")
print("printing all t,u paris")
print(t_l)
print(u_l)

"""
# testing code: do not modify

from module_1_ECDSA_Cryptanalysis_tests import run_tests

run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP
)
