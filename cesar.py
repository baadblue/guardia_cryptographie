def cesar(chain, key):
    encoded_chain = ""
    for letter in chain:
        car = ord(letter)
        if (car >= 65 and car <= 90):
            encoded_chain += chr((car - 65 + key) % 26 + 65)
        elif (car >= 97 and car <= 122):
            encoded_chain += chr((car - 97 + key) % 26 + 97)
        else:
            encoded_chain += letter
    return encoded_chain

if __name__ == "__main__":
    chain = input("Entrer la chaine à chiffrer : ")
    key = int(input("Entrer la clé : "))
    print(cesar(chain, key))