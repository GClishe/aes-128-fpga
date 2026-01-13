
def transpose(matrix: list[list]) -> list[list]:

    # assumes a non-akward style array

    return [[col[i] for col in matrix] for i in range(len(matrix[0]))]


# Plaintext and key are of type bytes
# The bytes type is simply an array of bytes. For example: 

# a: bytes = b"Test message"
# b: str = "Test message"
# print(a[0], b[0])
# 
# >>> 84 T 

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long for AES-128.")
    
    temp_matrix = [[plaintext[i] for i in range(j, j+3)] for j in range(0,3)]    # transforms the plaintext into a matrix [[b0, b1, b2,b3],[b4, ... ], ... ]
    matrix = transpose(temp_matrix)         # transposes matrix into correct format for AES algorithm