bytes = b"Calm down my dude"
key = b"nice one m8"

byteslen = len(bytes)
keylen = len(key)

def encrypt(bytes, key):
    array = []
    count = 0
    m = keylen-1
    for byte in bytes:
        val = byte^key[count]
        array.append(val)
        if count is m:
            count = 0
        else:
            count += 1
    
    encrypted = ""
    for c in array:
        encrypted += chr(c)
    
    return encrypted

def decrypt(string, key):
    arr = []
    for c in string:
        arr.append(ord(c))
    
    output = ""
    count = 0
    m = keylen-1 
    for v in arr:
        val = v^key[count]
        output += chr(val)
        if count is m:
            count = 0
        else:
            count += 1
    
    return output

enc = encrypt(bytes, key)
dec = decrypt(enc, key)

print("Unencrypted: {}\nKey: {}\n\n".format(bytes, key))
print("Encrypted (XOR):\n{}\n".format(enc))
print("Decrypted:\n{}".format(dec))