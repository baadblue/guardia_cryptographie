from cesar import cesar

def vigenere(chain, key):
    keyIndex = 0
    key = key.upper()
    newChain = ""
    for elt in chain:
        if elt.isalpha():
            newChain += cesar(elt, ord(key[keyIndex])-65)
        else:
            newChain += elt
        if keyIndex == len(key)-1:
            keyIndex = 0
        else:
            keyIndex += 1
    return newChain

if __name__ == "__main__":
    print(vigenere("Hello world!", "testee"))