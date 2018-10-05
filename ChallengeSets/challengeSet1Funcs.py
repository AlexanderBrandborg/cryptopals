from binascii import *  # Conversion between ascii and binary
import codecs  # Used in decoding base64
from functools import reduce  # Reduction statements
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Used for AES encryption
from cryptography.hazmat.backends import default_backend  # Used for AES encryption

# Frequency of letters in the english language, except for space which is a 'magic' frequency
frequencyDict = {
    ' ': 5, 'e': 12.02, 't': 9.10, 'o': 7.68, 'a': 8.12, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92,
    'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82,
    'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
}


def bytes_to_int(bytes):
    return int.from_bytes(bytes, byteorder='big', signed=False)


def get_number_of_bytes(number):
    """
    :param number: integer
    :return: number of bytes logically taken by input
    """
    number_of_bits = number.bit_length()
    number_of_bytes = int(number_of_bits / 8)
    if number_of_bits % 8 != 0:
        number_of_bytes += 1
    return number_of_bytes


def get_number_of_toggled_bits(number):
    """
    This uses Brian Kernighan’s Algorithm
    :param number: integer
    :return: amount of 1s in number
    """
    res = 0
    while number:
        number = number & (number - 1)
        res += 1
    return res


def access_bits_at_index(source, number_of_bits, index):
    """
    :param source: Integer where lookup is made
    :param number_of_bits: Size of section to read in bits
    :param index: Index to read from, going from most significant bit
    :return: integer representing the looked up bits
    """
    mask = (pow(2, number_of_bits) - 1)
    bits_to_full_block = (number_of_bits - (source.bit_length() % number_of_bits))

    # ensure size of mask is a multiplex of numberOfBits so that it can be used for indexing
    moved_mask = mask << (source.bit_length() + bits_to_full_block - number_of_bits)
    total_indices = int(moved_mask.bit_length() / number_of_bits)

    unmoved_result = (source & (moved_mask >> (index * number_of_bits)))  # Result caught
    result = unmoved_result >> (((total_indices - index) * number_of_bits) - number_of_bits)  # Result moved right

    return result


def get_block_at_index(bytes, idx, block_size):
    """
    :param bytes: byte array
    :param idx: block index
    :param block_size: size of block in bytes
    :return:
    """
    return bytes_to_int(bytes[idx * block_size: idx * block_size + block_size])


# Challenge 1
def encode_bits(unencoded_bits):
    """
    :param unencoded_bits:  Integer to be encoded
    :return: Base64 encoded byte array
    """
    encoded_string = ""
    look_up_table = \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
        "abcdefghijklmnopqrstuvwxyz" \
        "0123456789+/"
    bits_per_section = 6

    bits_to_full_block = (bits_per_section - unencoded_bits.bit_length() % bits_per_section)
    number_of_blocks = int((unencoded_bits.bit_length() + bits_to_full_block) / bits_per_section)

    for i in range(number_of_blocks):
        table_index = access_bits_at_index(unencoded_bits, bits_per_section, i)
        encoded_string += look_up_table[table_index]

    # Pads string if required to fill up 4 bytes
    for i in range(number_of_blocks, 4):
        encoded_string += "="

    return encoded_string.encode('ascii')


def new_base_64_encode(plain_bytes):
    """
    :param plain_bytes: byte array of hex values to be encoded
    :return: encoded byte array
    """
    bytes_per_block = 3
    num_full_blocks = int(len(plain_bytes) / bytes_per_block)

    blocks = [get_block_at_index(plain_bytes, i, bytes_per_block) for i in range(num_full_blocks)]

    #  Special case if the last block is not three bytes
    if len(plain_bytes) % bytes_per_block:
        blocks.append(get_block_at_index(plain_bytes, num_full_blocks, len(plain_bytes) % 3))

    cipher_bytes = b''.join([encode_bits(block) for block in blocks])
    return cipher_bytes


# Challenge 2
def fixed_xor(buffer1, buffer2):
    """
    :param buffer1: byte array
    :param buffer2: byte array
    :return: byte array containing the XOR'ed result of buffer1 and buffer2
    """
    if len(buffer1) != len(buffer2):
        Exception("Buffers not of equal length")

    return bytearray([x ^ y for x, y in zip(buffer1, buffer2)])


# Challenge 3
def single_byte_xor_decode(cipher_bytes):
    """
    Finds the most likely key used in XOR based on the frequency of plain text chars in the English language
    :param cipher_bytes: byte array xor encoded with an ascii char
    :return: decoded result, likelihood of result, key used
    """
    result = (bytearray(), 0, 0)
    number_of_ascii_characters = 255

    for key in range(number_of_ascii_characters):
        # Get result of xor
        repeated_keys = bytearray([key for _ in range(len(cipher_bytes))])
        plain_bytes = fixed_xor(cipher_bytes, repeated_keys)

        # Compute likelihood through lookups in frequencyDict
        frequency_dict_lookup = lambda x, y: x + frequencyDict.get(chr(y).lower(), 0)
        likelihood = reduce(frequency_dict_lookup, plain_bytes, 0)

        # Update result if current is more likely
        highest_likelihood = result[1]
        result = result if likelihood < highest_likelihood else (plain_bytes, likelihood, key)

    return result


# Challenge 4
def find_xor_encoded_line_in_file(filename):
    """
    :param filename: name of file containing lines, where one is xor encoded with an ascii character
    :return: decoded result, likelihood of result, key used for the most likely line
    """
    with open(filename) as file:
        xor_line = lambda x: single_byte_xor_decode(unhexlify(x.strip()))  # gets most likely decoding of line
        most_likely_result = reduce(lambda x, y: x if y[1] < x[1] else y, map(lambda x: xor_line(x), file))

    return most_likely_result


# Challenge 5
def repeating_xor(plain_bytes, key):
    """
    :param plain_bytes: Byte array to encrypt
    :param key:  Key to encrypt with
    :return: byte array containing cipher text
    """
    repeated_keys = bytearray([key[idx % len(key)] for idx in range(len(plain_bytes))])
    cipher_text = fixed_xor(plain_bytes, repeated_keys)
    return cipher_text


# Challenge 6
def hamming_distance(bytes1, bytes2):
    """
    :param bytes1: byte array
    :param bytes2: byte array
    :return: hamming_distance between sequences of bytes
    """
    compound_toggled_bits_in_xor = lambda x, y: x + get_number_of_toggled_bits(y[0] ^ y[1])
    return reduce(compound_toggled_bits_in_xor, zip(bytes1, bytes2), 0)


def compute_normalized_distance(cipher_text, key_size, number_of_samples):
    """
    :param cipher_text: string with encoded text to sample from
    :param key_size: size of key
    :param number_of_samples: number of hamming distances to compute
    :return:
    """
    # Creating block pairs, yielding a sequence of (b1, b2) (b2, b3) ...
    number_of_blocks = number_of_samples + 2
    cipher_blocks = [cipher_text[key_size * (i - 1): key_size * i] for i in range(1, number_of_blocks)]
    cipher_block_pairs = zip(cipher_blocks, cipher_blocks[1:])  # shifted coupling of sampled bytes

    # Computing hamming distance between all pairs and normalizing
    total_distance = reduce(lambda x, y: x + hamming_distance(y[0], y[1]), cipher_block_pairs, 0)
    normalized_distance = float(total_distance) / (key_size * number_of_samples)
    return normalized_distance


def compute_key_and_plain_text(cipher_text, key_size):
    """
    :param cipher_text: string with encoded text to decode
    :param key_size: size of key
    :return: (key, decoded text) tuple
    """
    # Create blocks of bytes, which must be encoded with the same byte
    block_bytes = [bytearray() for _ in range(key_size)]
    for idx, byte in enumerate(cipher_text):
        block_bytes[idx % key_size].append(byte)

    # For each block compute most likely encoding byte, create key and decode text
    key = bytearray([single_byte_xor_decode(block)[2] for block in block_bytes])
    decoded_text = repeating_xor(cipher_text, key)
    return key, decoded_text


def break_repeating_xor(filename):
    """
    :param filename: text file encoded with a repeating xor
    :return: list of (key, plain text) tuples
    """
    # Load text and base 64 decode it
    with open(filename, "r") as file:
        stripped_text = file.read().strip()
    cipher_text = codecs.decode(bytearray(stripped_text, 'ascii'), 'base64')

    # Find most likely keys in range of sizes according to hamming distance
    low_key_size = 2
    high_key_size = 40
    keys_sizes = range(low_key_size, high_key_size)

    number_of_samples = 3
    hamming_distances = [compute_normalized_distance(cipher_text, key, number_of_samples) for key in keys_sizes]

    number_likely_keys = 3
    likely_key_sizes = sorted(keys_sizes, key=lambda i: hamming_distances[i - low_key_size])[:number_likely_keys]

    # Find most likely keys per size
    results = [compute_key_and_plain_text(cipher_text, keySize) for keySize in likely_key_sizes]

    return results


# Challenge 7
def decrypt_aes_with_key(filename, key):
    """
    :param filename: file with cipher text encoded by AES in ECB mode using key
    :param key: byte array containing key
    :return: decoded text in byte array
    """
    # Load text and base 64 decode it
    with open(filename, "r") as file:
        striped_text = file.read().strip()
    cipher_text = codecs.decode(bytearray(striped_text, 'ascii'), 'base64')

    # Decrypt
    decrypter = (Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())).decryptor()
    plain_text = decrypter.update(cipher_text) + decrypter.finalize()

    return plain_text


# Challenge 8
def duplicates_in_line(line_bytes):
    """
    :param line_bytes: byte_array
    :return: number of 16 byte blocks in input, which are duplicates
    """
    block_size = 16
    block_num = int(len(line_bytes) / block_size)
    integer_blocks = [get_block_at_index(line_bytes, i, block_size) for i in range(block_num)]
    return len(integer_blocks) - len(set(integer_blocks))


def detect_ecb_encoded_line(filename):
    """
    :param filename: text file with a single line encoded using AES in ECB mode
    :return: line number and detected line
    """
    with open(filename) as file:
        lines = [(duplicates_in_line(a2b_hex(line.strip())), idx, line) for idx, line in enumerate(file)]
    return max(lines, key=lambda x: x[0])[1:]


if __name__ == "__main__":
    res1 = new_base_64_encode(a2b_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
    res2 = fixed_xor(a2b_hex("1c0111001f010100061a024b53535009181c"), a2b_hex("686974207468652062756c6c277320657965"))
    res3 = single_byte_xor_decode(unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
    res4 = find_xor_encoded_line_in_file("../data/challenge1/challenge4text")
    res5 = repeating_xor("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal".encode('ascii'), "ICE".encode('ascii'))
    res6 = hamming_distance(bytearray("this is a test", 'ascii'), bytearray("wokka wokka!!!", 'ascii'))
    res7 = break_repeating_xor("../data/challenge1/challenge6text")
    res8 = decrypt_aes_with_key("../data/challenge1/challenge7text", bytes("YELLOW SUBMARINE", 'ascii'))
    res9 = detect_ecb_encoded_line("../data/challenge1/challenge8text")
    d = "bug"
