from entropy import calculate_entropy
import math

def calculate_redondance(password):
    entropy = calculate_entropy(password)
    max_entropy = (math.log2(90)*len(password))
    print(entropy)
    print(max_entropy)
    return 1 - (entropy/max_entropy)

print(calculate_redondance("Hell_Yeah!99"))

'''
Hell_Yeah!99
'''