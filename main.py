from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import matplotlib.pyplot as plt
import os
# note - must install pycrptodome, pillow, and matplotlib to run


# PKCS#7 Padding
# default block size of 16 bytes for AES
def pkcs7_pad(data, block_size=16):
    # use mod to find number of bytes in last partial block then find the difference from block length
    padding_len = block_size - (len(data) % block_size)
    # append padding bytes to data
    return data + bytes([padding_len] * padding_len)

#unpad data
def pkcs7_unpad(data):
    #last element of padding tells us how long the padding is
    padding_len = data[-1]
    #check valid length
    if padding_len > 16:
        raise ValueError("Invalid padding")
    #slice padding bytes from data and return result
    return data[:-padding_len]


# ECB Encryption
def ecb_encrypt(data, key):
    #create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #empty bytes object to use for concatenation
    encrypted = b""
    #iterate through 16 byte blocks and append encrypted block
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        encrypted += cipher.encrypt(block)
    return encrypted


# ECB Decryption
def ecb_decrypt(data, key):
    #create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #create byte object for concatenation of decrypted blocks
    decrypted = b""
    #iterate through blocks and append decrypted blocks to byte object
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        decrypted += cipher.decrypt(block)
    return decrypted


# CBC Encryption
def cbc_encrypt(data, key, iv):
    #create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #initialize byte string
    encrypted = b""
    #prev_block begins as initialization vector
    prev_block = iv
    #iterate through 16 byte blocks
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        # xor the block with previous ciphertext
        #zip combines current plaintext block with previous block byte by byte for xor
        block = bytes(a ^ b for a, b in zip(block, prev_block))
        #encrypt the xored block
        encrypted_block = cipher.encrypt(block)
        #append encrypted block to result
        encrypted += encrypted_block
        #set previous block equal to current encrypted block
        prev_block = encrypted_block
    return encrypted


# CBC Decryption
def cbc_decrypt(data, key, iv):
    #create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #create byte string
    decrypted = b""
    #initial prev_block is the initialization vector
    prev_block = iv
    #iterate through 16 byte blocks
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        #decrypt current block
        decrypted_block = cipher.decrypt(block)
        # xor the decrypted block with previous block
        decrypted += bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        # set previous block equal to current block
        prev_block = block
    return decrypted


# BMP Header Handling
def read_bmp_header(filename):
    # Read and return BMP header (first 54-138 bytes)
    with open(filename, "rb") as file:
        header = file.read(138)
    return header


def process_image(filename):
    # Extract BMP header and data
    header = read_bmp_header(filename)
    # read file body and store in data
    with open(filename, "rb") as file:
        data = file.read()[len(header):]
    return header, data


# Encrypt Image
# Combine EBC and CBC encryption methods
# optional parameters for key and iv if you already have them otherwise create them using get_random_bytes
def encrypt_image(filename, mode, key=None, iv=None):
    header, data = process_image(filename)
    key = key or get_random_bytes(16)
    iv = iv or get_random_bytes(16)
    # pad data before encrypting
    data = pkcs7_pad(data)

    #encrypt data in specified mode
    if mode == "ECB":
        encrypted_data = ecb_encrypt(data, key)
    elif mode == "CBC":
        encrypted_data = cbc_encrypt(data, key, iv)
    else:
        raise ValueError("Invalid mode")

    #create output bmp file for encrypted image
    output_file = f"{os.path.splitext(filename)[0]}_{mode.lower()}_encrypted.bmp"
    #write header and initialization vector to file (if CBC) then write encrypted data
    with open(output_file, "wb") as file:
        file.write(header)
        if mode == "CBC":
            file.write(iv)  # Store IV for CBC
        file.write(encrypted_data)
    return output_file


# Decrypt Image
# combine EBC and CBC encryption methods
def decrypt_image(filename, mode, key, iv=None):
    # read header from encrypted bmp file
    header = read_bmp_header(filename)
    # read initialization vector (if CBC) then read file body
    with open(filename, "rb") as file:
        file.read(len(header))  # Skip header
        iv = file.read(16) if mode == "CBC" else iv
        data = file.read()

    #call corresponding decryption function
    if mode == "ECB":
        decrypted_data = ecb_decrypt(data, key)
    elif mode == "CBC":
        decrypted_data = cbc_decrypt(data, key, iv)
    else:
        raise ValueError("Invalid mode")

    #unpad the result
    decrypted_data = pkcs7_unpad(decrypted_data)
    #create output file
    output_file = f"{os.path.splitext(filename)[0]}_{mode.lower()}_decrypted.bmp"
    #write data to output file
    with open(output_file, "wb") as file:
        file.write(header)
        file.write(decrypted_data)
    return output_file


# Display BMP Image Comparison
# We used Pillow to help with opening image files in matplotlib
def display_images(original_file, ecb_file, cbc_file):

    #store image files in array and titles at corresponding index in titles array
    images = [original_file, ecb_file, cbc_file]
    titles = ["Original", "ECB Encrypted", "CBC Encrypted"]

    #create figure of width 15 units and height 5 units for displaying images side by side
    plt.figure(figsize=(15, 5))
    for i, img_file in enumerate(images):
        img = Image.open(img_file) #open image file
        plt.subplot(1, 3, i + 1) #create subplot for current image
        plt.imshow(img) #display image
        plt.title(titles[i]) # add the title
        plt.axis("off") #turn off axes because they dont make sense in this context
    plt.show() #render the finished plot

def test():
    print("test")
# Main Function
if __name__ == "__main__":
    # Input Image
    original_file = "example.bmp"

    # Generate AES Key and IV
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Encrypt Image in ECB and CBC Modes
    ecb_file = encrypt_image(original_file, "ECB", key)
    cbc_file = encrypt_image(original_file, "CBC", key, iv)

    # Decrypt Images (for validation)
    decrypt_image(ecb_file, "ECB", key)
    decrypt_image(cbc_file, "CBC", key, iv)

    # Display Results
    display_images(original_file, ecb_file, cbc_file)
