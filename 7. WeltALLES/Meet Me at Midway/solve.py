import json
import sympy 

word_dictionary = json.load(open("word_dictionary.json"))

blocks = [
    ['20999', '20994', '20907', '20928', '20947', '20946', '20967', '20976'],
    ['20962', '20915', '20928', '20949', '20968', '20904', '20975', '20094'],
    ['20916', '20033', '20046', '20067', '20086', '20943', '20093', '20002'],
    ['20059', '20054', '20067', '20936', '20004', '20003', '20014', '20033'],
    ['20971', '20072', '20085', '20096', '20952', '20021', '20032', '20041'],
    ['20962', '20096', '20928', '20982', '20043', '20042', '20097', '20069'],
    ['20006', '20011', '20024', '20035', '20938', '20060', '20071', '20036'],
    ['20024', '20139', '20061', '20150', '20179', '20934', '20186', '20105'],
    ['20142', '20147', '20974', '20178', '20197', '20958', '20104', '20123'],
    ['20287', '20129', '20974', '20150', '20334', '20033', '22864', '23048', '37898', '21091', '21366', '21534', '31053', '21612'],
    ]
blocks = [[int(b) for b in row] for row in blocks]
    
def false_subtraction(a,b):
    l1 = list(map(int,str(a)))
    l2 = list(map(int,str(b)))
    l1 = [0] * (5 - len(l1)) + l1
    l2 = [0] * (5 - len(l2)) + l2
    l3 = [(x - y) % 10 for x, y in zip(l1,l2)]
    return int("".join(map(str, l3)))
 
 
known_plaintext = "As I sit down to write here amidst".upper().split(" ")
possible_keys = word_dictionary.keys()

plaintext = []
found_keys = []

for i, column in enumerate(zip(*blocks)):

    # assume the same key is used for the whole column, then each word must decode to something in the dictionary
    # -> artifact from when we didn't know abput the known plaintext
    keys = set.intersection(*(set(false_subtraction(y, x) for x in possible_keys) for y in column))
    
    for k in keys:
        decoded = list(word_dictionary[str(false_subtraction(a, k))] for a in column)
        
        # use known plaintext
        if decoded[0] == known_plaintext[i]:
            found_keys.append(k)
            plaintext.append(decoded)
    
print("Keys", found_keys)

for row in zip(*plaintext):
    print(" ".join(row))

rem_cipher = 37898, 21091, 21366, 21534, 31053, 21612

# at this point, realize that the keys are consecutive primes
rem_keys = [sympy.nextprime(found_keys[-1])]
while len(rem_keys) < len(rem_cipher):
    rem_keys.append(sympy.nextprime(rem_keys[-1]))

solution = list(row)

for c, k in zip(rem_cipher, rem_keys):
    solution.append(word_dictionary[str(false_subtraction(c, k))])
    
print("\n\nSolution")
print(" ".join(solution))
# -> NOW IS THE TIME FOR ALL GREAT SPACE MATHEMATICIANS TO COME OUT AND PLAY
