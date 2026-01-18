
def transpose(matrix: list[list]) -> list[list]:

    # assumes a non-akward style array

    return [[col[i] for col in matrix] for i in range(len(matrix[0]))]

def bytewise_XOR(b1: bytes, b2: bytes) -> bytes:
    if len(b1) != len(b2):
        raise ValueError("Words must be same length to XOR")
    b1_list = list(b1)      # converts b1 to list of ints
    b2_list = list(b2)      # converts b2 to list of ints
    res_list = [b1_list[i] ^ b2_list[i] for i in range(len(b1))]    # XORS corresponding elements in b1, b2
    return bytes(res_list)

def left_shift(word: list[int], times: int = 1) -> list[int]:

    for _ in range(times):
        temp = word[1:]                  # moves all but the first element to the left
        temp.append(word[0])             # adds first element back to the end
        word = temp

    return word              # converts list of ints back to a bytes object

def ShiftRows(matrix: list[list[int]]) -> list[list[int]]:
    """
    Apply the AES ShiftRows transformation to the state matrix.

    Cyclically left-shifts each row of the 4×4 AES state by an
    offset equal to the row index. The first row is unchanged,
    the second row is shifted left by one byte, the third by two,
    and the fourth by three.

    :param matrix: Current AES state represented as a 4×4
                   matrix of integers in the range 0–255.
    :type matrix: list[list[int]]
    :return: New AES state after the ShiftRows operation,
             represented as a 4×4 matrix of integers.
    :rtype: list[list[int]]
    """
    new_mat = []

    for i,row in enumerate(matrix):
        new_mat.append(left_shift(row, times=i))
    
    return new_mat

def substitute_byte(byte: int) -> int:             
    
    Sbox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )
    

    new_val = Sbox[byte]
    return new_val     

def SubBytes(matrix: list[list[int]]) -> list[list[int]]:
    """
    Apply the AES SubBytes transformation to the state matrix.

    Replaces each byte in the 4×4 AES state matrix with its 
    corresponding value from the AES S-box.

    :param matrix: Current AES state represented as a 4×4
                   matrix of integers in the range 0–255.
    :type matrix: list[list[int]]
    :return: New AES state after the SubBytes operation,
             represented as a 4×4 matrix of integers.
    :rtype: list[list[int]]
    """

    return [[substitute_byte(matrix[i][j]) for j in range(4)] for i in range(4)]

def g(word: bytes, round_num: int) -> bytes:
    """
    Apply AES key-schedule g() transofrmation to a 4-byte word 
    
    :param word: 4-byte word to be rotated
    :type word: bytes
    :param round_num: current round number
    :type round_num: int
    :return: Rotated word
    :rtype: bytes
    """
    if len(word) != 4: 
        raise ValueError("Improper word length. g() requires 4-byte word")
    if round_num not in range(1,11):
        raise ValueError("AES-128 uses round constants for rounds 1–10.")
    
    temp = list(word)
    rotated_word = left_shift(temp)                                         # first step is to left rotate the word
    substituted_word = list(map(substitute_byte, rotated_word))             # applies substitute_byte function to each byte in rotated_word. list(rotated_word) is an array of ints

    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]     # the first byte in the substituted word is then XOR'd with the value in the RCON table corresopnding to the round number

    new_first_val = substituted_word[0] ^ RCON[round_num - 1]               # XORs first byte with RCON value
    substituted_word[0] = new_first_val                                     # replaces first byte with new value
    
    return bytes(substituted_word)      # converts substituted_word (list of ints) to a bytes object and returns. 

def key_expansion(key: bytes) -> list[bytes]:
    """
    Expand a 128-bit AES key into round keys.

    Derives 11 round keys rqeuired for AES-128 key scheduling, including the initial round key (round 0).
    
    :param key: 16-byte AES-128 cipher key. 
    :type key: bytes
    :return: List of 11 round keys, each a 16-byte 'bytes' object, ordered from round 0 through round 10
    :rtype: list
    """
    if len(key) != 16:
        raise ValueError("Key expansion failed. Key must be 16 bytes long for AES-128.")

    words: list = [key[0:4], key[4:8], key[8:12], key[12:16]]         # splits the key into four words, each four bytes long

    # each round key is 4 words. W0 thru W3 is round 0 ... W40 thru W43 is round 10. We need 44 words for 10 rounds.
    # every fourth word goes thru a transformation "g" before being XOR'd
    for i in range(4,44):  
        if (i % 4 != 0):
            nextWord = bytewise_XOR(words[i-4], words[i-1])
            words.append(nextWord)
        else:
            nextWord = bytewise_XOR(words[i-4], g(words[i-1], i // 4))  # we XOR the i-4 word with g(w[i-1]). we use i // 4 to determine round number
            words.append(nextWord)
    round_keys = [words[4*r : 4*r + 4] for r in range(11)]              # groups the words into sets of 4, with one set of words being one round key. round_keys is of type list(list(bytes))

    return [b"".join(word for word in round) for round in round_keys]   # concatenates the 4 words in each round to form 11 rounds of 16-byte keys. return type is list(bytes)

def AddRoundKey(state: list[list[int]], round_key: bytes) -> list[list[int]]:
    """
    XOR the AES state with a round key.

    Performs the AddRoundKey step of the AES algorithm by
    XORing each byte of the 4×4 state matrix with the
    corresponding byte of the round key.

    :param state: Current AES state represented as a 4×4
                  matrix of integers in the range 0–255.
    :type state: list[list[int]]
    :param round_key: 16-byte round key derived from the
                      AES key schedule.
    :type round_key: bytes
    :return: New AES state after the AddRoundKey operation,
             represented as a 4×4 matrix of integers.
    :rtype: list[list[int]]
    """
    temp_key_matrix = [[round_key[i] for i in range(4*j, 4*j+4)] for j in range(0,4)]       # converts the round key into a row-major matrix
    key_matrix = transpose(temp_key_matrix)                                                 # converts matrix to column-major format

    new_state = [[state[i][j] ^ key_matrix[i][j] for j in range(4)] for i in range(4)]      # bytewise XOR on corresponding elements in the matrices.
    # an alternative is new_state = [list(bytewise_XOR(bytes(state[row]), bytes(key_matrix[row]))) for row in range(4)], but there is no need for all the additional type conversions

    return new_state
        
def GF_multiply(v1: list[int], v2: list[int]) -> int:
    """
    Multiply two 4-byte vectors in GF(2^8) using polynomial arithmetic
    with reduction by the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
    (0x11b).

    Each element v1[i] is multiplied with v2[i] in GF(2^8). The four resulting
    products are then XORed together to produce the final result.

    The multiplication is performed by:
      1. Interpreting each byte as a polynomial over GF(2)
      2. Computing the polynomial product
      3. Reducing coefficients modulo 2
      4. Reducing the result modulo 0x11b

    :param v1: Length-4 list of integers (0–255) representing GF(2^8) elements
    :type v1: list[int]
    :param v2: Length-4 list of integers (0–255) representing GF(2^8) elements
    :type v2: list[int]
    :return: XOR of the four GF(2^8) products v1[i] · v2[i]
    :rtype: int
    """

    v_res = []
    for i in range(4):
        n1 = v1[i]
        n2 = v2[i]

        x1 = list(bin(n1))[2:][::-1]
        x2 = list(bin(n2))[2:][::-1]

        gf_x1 = [i for i in range(len(x1)) if x1[i] == '1']         # recovers exponents in GF representation of binary number
        gf_x2 = [i for i in range(len(x2)) if x2[i] == '1']         # [0,1,1,0,1,0] --> [1,2,4] (from GF(011010) = x + x^2 + x^4)

        digits = []
        for i in gf_x2:
            for j in gf_x1:
                digits.append(i + j)

        counts = {}
        for n in digits:                                            # counts occurrences of polynomial terms in GF representation
            if n not in counts:
                counts[n] = 1
            else:
                counts[n] += 1

        digits2 = [n for n in counts if counts[n] % 2 == 1]         # removes terms in GF polynomial if their exponent appears an even number of times.

        y = [0] * 16
        for i in digits2:
            y[i] = 1

        res_str = "".join(str(n) for n in y).rstrip("0")[::-1]      # converts y into binary number, MSB first (type str). 
        res = int(res_str, base=2)                                  # converts to int type

        while res > 0x11b:                                          # reduces by 0x11b
            res = res ^ 0x11b

        v_res.append(res)
    
    return v_res[0] ^ v_res[1] ^ v_res[2] ^ v_res[3]                # XOR each element in v_res


def MixColumns(matrix: list[list[int]]) -> list[list[int]]:
    
    MDS_MATRIX = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ]

    result = []
    # MixColumns is a column operation. To extract columns, i use rows of the tranposed matrix. 
    for row in matrix:
        new_row = []
        for i in  range(4):
            new_row.append(GF_multiply(MDS_MATRIX[i], row)) # performs GF_multiply function on each row in the matrix. 



def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long for AES-128.")
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be 16 bytes long.")
    
    temp_matrix = [[plaintext[i] for i in range(4*j, 4*j+4)] for j in range(0,4)]    # transforms the plaintext into a matrix [[b0, b1, b2,b3], [b4, ... ], ... ]
    initial_matrix = transpose(temp_matrix)                 # transposes matrix into correct format for AES algorithm

    round_keys = key_expansion(key)                         # creates the keys to be used in each round
    
    state = AddRoundKey(state=initial_matrix, round_key=round_keys[0]) # performs initial AddRoundKey step before rounds 1 thru 10

    for round in range(1,10):
        state = SubBytes(state)
        state = ShiftRows(state)





   




