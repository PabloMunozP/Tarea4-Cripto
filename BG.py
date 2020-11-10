#import random
#import numpy
import os
import sys,base64,json


#function for checking if a number is prime
def is_prime_number(x):
    if x >= 2:
        for y in range(2,x):
            if not ( x % y ):
                return False
    else:
	    return False
    return True

#function for XORing two strings
def XOR(a,b):
    a,b = str(a),str(b)
    assert(len(a) <= len(b))
    result = ""
    for i in range(len(a)):
        result += str(int(a[i]) ^ int(b[i]))
    return result

#function for finding the modular inverse
def modInverse(a, m) : 
    a = a % m
    for x in range(1, m) : 
        if ((a * x) % m == 1) : 
            return x 
    return 1

#######################################################
###########         Key Generation          ###########
#######################################################

def key_generation(p,q):
    try:
        #making sure p and q are congruent to 
        assert(is_prime_number(p))
        assert(is_prime_number(q))
        assert(p % 4 == 3)
        assert(q % 4 == 3)
        #creating N, public key
        N = p * q
        #print("Public Key =", N)

        #split_string_m = str(m)
        print('Llave generada')
        return N

    except AssertionError as e:
        print('Error con los numeros elegidos: ', str(e))


#######################################################
###########            Encryption           ###########
#######################################################

def encrypt(msg,X0,key):
    X = []
    X.append(X0)
    #print('mensaje a cifrar: ',msg)    
    hash_bytes=''
    for char in msg:
        bin_text=str(bin(ord(char))).replace('0b','')
        while len(bin_text)<7:
            bin_text= '0'+bin_text
        #print(char,len(bin_text))
        hash_bytes+=bin_text
    #print(hash_bytes)
    b = ""
    L = len(str(hash_bytes))
    for i in range(L):
        string_x = bin(X[-1])[2:]
        size = len(string_x)
        b_i = string_x[size-1]
        b = b_i + b
        new_x = (X[i] ** 2) % key
        X.append(new_x)

    #print("message =", str(msg))
    #print("b =", b)
    str_m = str(hash_bytes)
    ciphertext = XOR(str_m, b)
    #print("Ciphertext =", bin_toAscii(ciphertext))
    XL = X[-1]
    X0 = X[0]
    XL_check = pow(X0,pow(2,L),key)
    assert (XL == XL_check)
    
    #this tuple represents what is being sent to Alice
    sent_message = (ciphertext, XL)
    #y = sent_message[1]
    return sent_message


#######################################################
###########            Decryption           ###########
#######################################################
def decrypt(p,q,encrypted):

    ciphertext,XL=encrypted
    XL=int(XL)
    L = len(str(ciphertext))
    N=p*q
    firstExponent = (((p+1)//4)**L) % (p-1)
    firstPhrase = "({}^{}) mod {}".format(XL,firstExponent,p)
    r_p = pow(XL,firstExponent,p)

    secondExponent = (((q+1)//4)**L) % (q-1)
    secondPhrase = "({}^{}) mod {}".format(XL,secondExponent,q)
    r_q = pow(XL,secondExponent,q)

    NEWX0 = (q*modInverse(q,p)*r_p + p*modInverse(p,q)*r_q)%N
    NEWX = []
    NEWX.append(NEWX0)


    b = ""
    for i in range(L):
        string_x = bin(NEWX[-1])[2:]
        size = len(string_x)
        b_i = string_x[size-1]
        b = b_i + b
        new_x = (NEWX[i] ** 2) % N
        NEWX.append(new_x)

    plaintext = XOR(ciphertext,b)
    #print("Plaintext  =", bin_toAscii(plaintext))
    return plaintext
    #checking decrypted ciphertext is the same as the original plaintext
    #assert(str(m) == str(plaintext))


def bin_toAscii(msg):
    msg_split=[msg[i:i+7] for i in range(0,len(msg),7)]
    #print(msg_split)
    salida=''
    for msg in msg_split:
        while len(msg) < 7:
            msg='0'+msg
        salida+=chr(int(msg,base=2))
    return salida

if __name__ == "__main__":
    #(p,q) Private key
    p=499  
    q=547 
    X0 =159201 
    hash= '$2b$12$T9wLk1D2C/Xt1NIHm65ri.hNH6hHFO1okTFKd2RlyRKj6EKqG8jly'
    m = '10010011001011000101001001100011100101001001010100111001111011110011001101011110001100010011001010000111011111011000111010011000110011101001001100100011011011101101101011110010110100110111011010001001110100100011011011010001001000100011010011111100011101111110101110101001000110100101111001001100101010010110110011110011010010100101111010101101101000101100101111100011000111111000110101011011001111001' # message 

    key = key_generation(p,q)
    encrypted = encrypt(hash,X0,key)
    decrypted = decrypt(p,q,encrypted)


