import binascii

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_BOX = {
    0: [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    1: [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    2: [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    3: [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    4: [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    5: [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    6: [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    7: [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ]
}

P = [
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

SHIFT_SCHEDULE = [
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
]

def permute(block, table):
    return [block[x-1] for x in table]

def hex_to_bin(hex_string):
    scale = 16
    num_of_bits = len(hex_string) * 4
    bin_string = bin(int(hex_string, scale))[2:].zfill(num_of_bits)
    return [int(bit) for bit in bin_string]

def bin_to_hex(bin_list):
    bin_str = ''.join(str(bit) for bit in bin_list)
    hex_str = hex(int(bin_str, 2))[2:].upper()
    return hex_str.zfill(len(bin_list) // 4)

def split_bits(bits, n):
    return [bits[i:i+n] for i in range(0, len(bits), n)]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def s_box_substitution(bits):
    output = []
    blocks = split_bits(bits, 6)
    for i, block in enumerate(blocks):
        row = (block[0] << 1) + block[5]
        column = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        val = S_BOX[i][row][column]
        bin_val = [int(x) for x in bin(val)[2:].zfill(4)]
        output.extend(bin_val)
    return output

def generate_keys(key_bits):
    key_permuted = permute(key_bits, PC1)
    C = key_permuted[:28]
    D = key_permuted[28:]
    round_keys = []
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        combined = C + D
        round_key = permute(combined, PC2)
        round_keys.append(round_key)
    return round_keys

def des_encrypt_block(block, round_keys):
    block = permute(block, IP)
    L, R = block[:32], block[32:]
    for i in range(16):
        R_expanded = permute(R, E)
        xor_result = xor(R_expanded, round_keys[i])
        sbox_result = s_box_substitution(xor_result)
        p_result = permute(sbox_result, P)
        new_R = xor(L, p_result)
        L, R = R, new_R
    combined = R + L
    final_block = permute(combined, FP)
    return final_block

def des_decrypt_block(block, round_keys):
    return des_encrypt_block(block, round_keys[::-1])

def des_encrypt(input_text, key):
    input_bytes = input_text.encode('ascii')
    while len(input_bytes) % 8 != 0:
        input_bytes += b'\x00'
    key_bits = []
    for byte in key:
        key_bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
    round_keys = generate_keys(key_bits)
    encrypted_bytes = b''
    for i in range(0, len(input_bytes), 8):
        block = input_bytes[i:i+8]
        block_bits = []
        for byte in block:
            block_bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
        encrypted_block_bits = des_encrypt_block(block_bits, round_keys)
        encrypted_block = bytearray()
        for b in range(0, 64, 8):
            byte = 0
            for bit in encrypted_block_bits[b:b+8]:
                byte = (byte << 1) | bit
            encrypted_block.append(byte)
        encrypted_bytes += bytes(encrypted_block)
    encrypted_hex = binascii.hexlify(encrypted_bytes).decode('ascii')
    return encrypted_hex

def des_decrypt(encrypted_hex, key):
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    key_bits = []
    for byte in key:
        key_bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
    round_keys = generate_keys(key_bits)
    decrypted_bytes = b''
    for i in range(0, len(encrypted_bytes), 8):
        block = encrypted_bytes[i:i+8]
        block_bits = []
        for byte in block:
            block_bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
        decrypted_block_bits = des_decrypt_block(block_bits, round_keys)
        decrypted_block = bytearray()
        for b in range(0, 64, 8):
            byte = 0
            for bit in decrypted_block_bits[b:b+8]:
                byte = (byte << 1) | bit
            decrypted_block.append(byte)
        decrypted_bytes += bytes(decrypted_block)
    decrypted_text = decrypted_bytes.rstrip(b'\x00').decode('ascii')
    return decrypted_text

if __name__ == "__main__":
    input_text = "Password"  
    key = b'\xA1\xB1\xC1\xA1\xA1\xA1\xA1\x11'  
    encrypted_text = des_encrypt(input_text, key)
    decrypted_text = des_decrypt(encrypted_text, key)
    print(f"Вхідний текст: {input_text}")
    print(f"Зашифрований текст (Hex): {encrypted_text}")
    print(f"Розшифрований текст: {decrypted_text}")
