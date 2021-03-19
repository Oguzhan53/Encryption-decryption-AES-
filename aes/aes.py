# BIL 470 - HW
# Oguzhan SEZGIN
# 1801042005
SBox = [
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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

invSBox = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

roundSize = 10


def shiftRows(matrix):  # This function shifts rows
    t = []
    for i in range(len(matrix)):
        t.append(matrix[i].copy())
    for i in range(1, len(matrix)):
        for j in range(len(matrix[i])):
            matrix[i][j] = t[i][(j + i) % len(t)]


def invShiftRows(matrix):  # This function does inverse of shift rows
    t = []
    for i in range(len(matrix)):
        t.append(matrix[i].copy())

    for i in range(1, len(matrix)):
        for j in range(len(matrix[i])):
            matrix[i][j] = t[i][(j + (len(t) - i)) % len(t)]


def subsByt(s):  # This function does byte substitution
    for i in range(len(s)):
        for j in range(len(s[i])):
            s[i][j] = SBox[s[i][j]]


def invSubsByt(s):  # This function does inverse of  byte substitution
    for i in range(len(s)):
        for j in range(len(s[i])):
            s[i][j] = invSBox[s[i][j]]


def addPad(plaintext):  # This function adds pad to end of the message if the message shorter than 16 byte
    reqPad = 16 - (len(plaintext) % 16)
    if reqPad == 16:
        return plaintext
    padding = bytes([plaintext[0] ^ plaintext[1]] * reqPad)

    return plaintext + padding


def removePad(plaintext):  # This function removes pad from end of the message if pad has been added
    for i in range(len(plaintext)):
        if plaintext[i] == (plaintext[0] ^ plaintext[1]):
            for j in range(i, len(plaintext)):
                if plaintext[j] != (plaintext[0] ^ plaintext[1]):
                    break
            if j == len(plaintext) - 1:
                return plaintext[:i]
                break

    return plaintext


def mixColumns(matrix):  # This function mixes columns
    for i in range(len(matrix)):
        t = matrix[i][0]
        t1 = t
        for j in range(1, len(matrix[i])):
            t ^= matrix[i][j]
        for j in range(len(matrix[i])):
            if j == len(matrix[i]) - 1:
                matrix[i][j] ^= t ^ galoiMult(matrix[i][j] ^ t1)
            else:
                matrix[i][j] ^= t ^ galoiMult(matrix[i][j] ^ matrix[i][j + 1])


def invMixColumns(matrix):  # This function does inverse of mix columns
    for i in range(len(matrix)):
        eCol = galoiMult(galoiMult(matrix[i][0] ^ matrix[i][2]))
        oCol = galoiMult(galoiMult(matrix[i][1] ^ matrix[i][3]))
        for j in range(len(matrix[i])):
            if j % 2 == 0:
                matrix[i][j] ^= eCol
            else:
                matrix[i][j] ^= oCol

    mixColumns(matrix)


def galoiMult(a):  # This function does galoi multiplication for mix column operation
    fl = a & 0x80
    a <<= 1
    if fl:
        a ^= 0x1B
        a &= 0xFF
    return a


def xorBytes(a, b):  # This function does xor
    ta = []
    tb = []
    for i in range(len(a)):
        ta.append(a[i])
        tb.append(b[i])
    xor = []
    for i in range(len(a)):
        xor.append(ta[i] ^ tb[i])

    bytXor = []
    for i in range(len(xor)):
        bytXor.append(xor[i])
    bytXor = bytes(bytXor)
    return bytXor


def addRoundKey(matrix, key):  # This function add rounds key in all aes round
    for i in range(len(matrix)):
        for j in range(len(matrix)):
            matrix[i][j] ^= key[i][j]


def convertMatrix(byt):  # This function convert byte array to matrix
    matrix = []
    tempList = []
    for i in range(len(byt)):
        tempList.append(byt[i])
        if (i + 1) % 4 == 0 and (i + 1) >= 4:
            matrix.append(tempList)
            tempList = []

    return matrix


def convertByte(matrix):  # This function convert matrix to byte array
    arr = []
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            arr.append(matrix[i][j])
    byt = bytes(arr)

    return byt


def seperateBlocks(text):  # This function separate message into blocks if message length > 16 bytes
    blocks = []
    for i in range(0, len(text), 16):
        blocks.append(text[i:i + 16])
    return blocks


def combineBlocks(blocks):  # This function combine message blocks
    text = b''
    for i in range(len(blocks)):
        text += blocks[i]
    return text


def expandKey(master_key):  # This function expands key for create each round key
    if len(master_key) == 16:
        expandedKey = convertMatrix(master_key)
        columnSize = len(master_key) // 4

        i = 0
        while len(expandedKey) < 44:
            word = list(expandedKey[-1])
            if len(expandedKey) % columnSize == 0:
                word.append(word.pop(0))
                for j in range(len(word)):
                    word[j] = SBox[j]
                word[0] ^= i
                i += 1

            word = xorBytes(word, expandedKey[-columnSize])
            expandedKey.append(word)

        roundKeys = []
        for i in range(0, len(expandedKey), columnSize):
            tlist = expandedKey[i:i + 4]
            roundKeys.append(tlist)
        return roundKeys
    else:
        raise Exception("key size must be 16 byte")


def encBlock(plaintext, key):  # This function encrypts block according to the aes algorithm
    if len(plaintext) != 16:
        plaintext = addPad(plaintext)
    roundKeys = expandKey(key)
    plainByt = convertMatrix(plaintext)

    addRoundKey(plainByt, roundKeys[0])

    for i in range(1, roundSize):
        subsByt(plainByt)
        shiftRows(plainByt)
        mixColumns(plainByt)
        addRoundKey(plainByt, roundKeys[i])

    subsByt(plainByt)
    shiftRows(plainByt)
    addRoundKey(plainByt, roundKeys[-1])

    return convertByte(plainByt)


def decBlock(ciphertext, key):  # This function decrypts block according to the aes algorithm
    roundKeys = expandKey(key)
    cipherByte = convertMatrix(ciphertext)

    addRoundKey(cipherByte, roundKeys[-1])
    invShiftRows(cipherByte)
    invSubsByt(cipherByte)

    for i in range(roundSize - 1, 0, -1):
        addRoundKey(cipherByte, roundKeys[i])
        invMixColumns(cipherByte)
        invShiftRows(cipherByte)
        invSubsByt(cipherByte)

    addRoundKey(cipherByte, roundKeys[0])
    chiperText = convertByte(cipherByte)
    chiperText = removePad(chiperText)
    return chiperText


def encModeCbc(plainText, key, iv):  # This function encrypts blocks according to the aes algorithm on CBC mode
    if len(iv) != 16:
        raise Exception("Initial vector size must be 16 byte")
    plainText = addPad(plainText)

    chiperTextBlocks = []
    previous = iv
    plaTextBlocks = seperateBlocks(plainText)

    for plaintextBlock in plaTextBlocks:
        chiperTextBlock = xorBytes(plaintextBlock, previous)
        chiperTextBlock = encBlock(chiperTextBlock, key)
        previous = chiperTextBlock
        chiperTextBlocks.append(chiperTextBlock)

    chiperText = combineBlocks(chiperTextBlocks)

    return chiperText


def decModeCbc(ciphertext, key, iv):  # This function decrypts blocks according to the aes algorithm on CBC mode
    if len(iv) != 16:
        raise Exception("Initial vector size must be 16 byte")

    plainTextBlocks = []
    previous = iv
    chpTextBlocks = seperateBlocks(ciphertext)

    for cipherTextBlock in chpTextBlocks:
        plainTextBlock = decBlock(cipherTextBlock, key)
        plainTextBlock = xorBytes(previous, plainTextBlock)
        plainTextBlocks.append(plainTextBlock)
        previous = cipherTextBlock

    plainText = combineBlocks(plainTextBlocks)
    plainText = removePad(plainText)
    return plainText


def encModeOfb(plainText, key, iv):  # This function encrypts blocks according to the aes algorithm on OFB mode
    if len(iv) != 16:
        raise Exception("Initial vector size must be 16 byte")

    chiperTextBlocks = []
    previous = iv
    plainTextBlocks = seperateBlocks(plainText)

    for plaintext_block in plainTextBlocks:
        cipherTextBlock = encBlock(previous, key)
        previous = cipherTextBlock
        cipherTextBlock = xorBytes(plaintext_block, cipherTextBlock)
        chiperTextBlocks.append(cipherTextBlock)

    chiperText = combineBlocks(chiperTextBlocks)
    return chiperText


def decModeOfb(cipherText, key, iv):  # This function decrypts blocks according to the aes algorithm on CBC mode
    if len(iv) != 16:
        raise Exception("Initial vector size must be 16 byte")

    plainTextBlocks = []
    previous = iv
    chpTextBlocks = seperateBlocks(cipherText)

    for ciphertext_block in chpTextBlocks:
        block = encBlock(previous, key)
        plainTextBlock = xorBytes(ciphertext_block, block)
        plainTextBlocks.append(plainTextBlock)
        previous = block

    plainText = combineBlocks(plainTextBlocks)

    return plainText


def createHashCode(text, key, iv):
    chiperText = encModeOfb(text, key, iv)
    hashCode = chiperText[-16:]
    return hashCode


def aesBlockTest():
    print("\n************** Aes Block Test ************** \n")
    key = b'this secret key.'
    message = b'Secret message.'
    chiperText = encBlock(message, key)
    print("Message : ", message)
    print("Chiper text : ", chiperText)
    plainText = decBlock(chiperText, key)
    print("Plain Text : ", plainText)


def difKeyDifChpTextTest():
    print("\n************** Different Cipher Text with Different Key Test ************** \n")
    key1 = b'1' * 16
    key2 = b'2' * 16
    message = b'Secret message.'
    chiperText1 = encBlock(message, key1)
    chiperText2 = encBlock(message, key2)
    print("Message : ", message)
    print("Chiper1 text : ", chiperText1)
    print("Chiper2 text : ", chiperText2)
    plainText1 = decBlock(chiperText1, key1)
    plainText2 = decBlock(chiperText2, key2)
    print("Plain Text1 : ", plainText1)
    print("Plain Text2 : ", plainText2)


def cbcModeTest():
    print("\n************** Aes Test on CBC Mode ************** \n")
    key = b'1' * 16
    message = b'This is a secret message and it must be encrypted by Aes with cbc mode'
    iv = b'3' * 16
    chiperText = encModeCbc(message, key, iv)
    print("Message : ", message)
    print("Chiper text : : ", chiperText)
    plainText = decModeCbc(chiperText, key, iv)
    print("Plain Text : ", plainText)


def ofbModeTest():
    print("\n************** Aes Test on OFB Mode ************** \n")
    key = b'2' * 16
    message = b'This is a secret message and it must be encrypted by Aes with ofb mode, so it will be encrypted by the aes encryptor.'
    iv = b'4' * 16
    chiperText = encModeOfb(message, key, iv)
    print("message : ", message)
    print("chiperText : ", chiperText)
    plainText = encModeOfb(chiperText, key, iv)
    print("plain text : ", plainText)


def difKeyCbc():
    print("\n************** Different Key Test on CBC Mode ************** \n")
    key1 = b'1' * 16
    key2 = b'2' * 16
    message = b'This is a secret message and it must be encrypted by Aes with cbc mode, so it will be encrypted by the aes encryptor.'
    iv = b'3' * 16
    chiperText = encModeCbc(message, key1, iv)
    print("message : ", message)
    print("chiperText : ", chiperText)
    plainText = decModeCbc(chiperText, key2, iv)
    print("plain text : ", plainText)


def difKeyOfb():
    print("\n************** Different Key Test on OFB Mode ************** \n")
    key1 = b'1' * 16
    key2 = b'2' * 16
    message = b'This is a secret message and it must be encrypted by Aes with ofb mode, so it will be encrypted by the aes encryptor.'
    iv = b'3' * 16
    chiperText = encModeOfb(message, key1, iv)
    print("message : ", message)
    print("chiperText : ", chiperText)
    plainText = encModeOfb(chiperText, key2, iv)
    print("plain text : ", plainText)


def hashCodeTest():
    print("\n************** Create Hash Code Test ************** \n")
    message = b'This is a secret message and it must be encrypted'
    key = b'1' * 16
    iv = b'3' * 16
    hashCode = createHashCode(message, key, iv)
    print("Hash code :", hashCode)


def fileHash():
    reafFile = open('myFile', 'rb')
    content = reafFile.read()
    key = b'1' * 16
    iv = b'3' * 16
    reafFile.close()
    hashCode = createHashCode(content, key, iv)
    hashCode = encBlock(hashCode, key)
    writeFile = open('myFile', 'ab')
    writeFile.write(hashCode)
    writeFile.close()
    return hashCode


def checkFile():
    key = b'1' * 16
    iv = b'3' * 16
    reafFile = open('myFile', 'rb')
    content = reafFile.read()

    temp = content[:-16]
    hashCode = content[-16:]
    newHash = createHashCode(temp, key, iv)
    newHash = encBlock(newHash, key)
    i = 0
    for h in hashCode:
        if (h != newHash[i]):
            return False
        i += 1
    return True


if __name__ == '__main__':
    aesBlockTest()
    difKeyDifChpTextTest()
    cbcModeTest()
    ofbModeTest()
    difKeyOfb()
    difKeyCbc()
    hashCodeTest()
    # fileHash()
    # checkFile()
