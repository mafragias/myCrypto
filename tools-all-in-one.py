"""
editor: mafragias

email: mafragias@hotmail.com

"""
from sys import exit
from copy import deepcopy
from math import ceil
import random
import string
import binascii

# Class Andvanced Encryption STandard
class AES(object):
    # Forward Rijndael Substitution Box 
    Sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
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
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    # Inverse Rijndael Substitution Box
    Ibox = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
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
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]              
    #Rcon: Rijndael constants
    Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d] 
    # Initialization Vector for CBC mode of operation in AES algorithm
    IV = [int(x) for x in range(0,16)]
          
    # Galois multiplication, returns the product of a and b in a finite field.
    # gmul by @fredgj
    def mul(self,a,b):
        p = 0
        while b:
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit:
                a ^= 0x11b
            b >>= 1
        return p
    
    # encryption based on AES Algorithm
    # Steps followed from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    # plaintext : bytes array 
    # key : bytes array
    def encrypt(self,plaintext,key,mode):
        # fill the blanks
        length = len(plaintext)
        if length%16!=0:
            for i in range(16 - length%16):
               plaintext.append('\0')
        # check if plaintext is an array of bytes
        if type(plaintext) == bytearray and type(key)==bytearray and (len(key)==16 or len(key)==24 or len(key)==32) and (mode=="ECB" or mode=="CBC"):
            t = int(ceil(float(len(plaintext))/16))     # number of iterations for the method
            chiphertext=[]  # initialization
            for i in range(0,t):
                nr = len(key)/4 + 6     # number of rounds
                
                if mode=="CBC" and i==0:
                    plaintext[i*16:i*16+16]=self.addRoundKey(plaintext[i*16:i*16+16],self.IV)
                elif mode=="CBC" and i!=0:
                    plaintext[i*16:i*16+16]=self.addRoundKey(plaintext[i*16:i*16+16],chiphertext[(i-1)*16:(i-1)*16+16])
                
                # generating round keys based on given key
                roundKeys = self.expandKey(key)
                # pre-round transformation
                chiphertext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16], roundKeys[0:16])
                # rounds
                for rnd in range(1,nr+1):
                    chiphertext[i*16:i*16+16] = self.subBytes(chiphertext[i*16:i*16+16])                
                    chiphertext[i*16:i*16+16] = self.shiftRows(chiphertext[i*16:i*16+16])
                    if rnd!=nr : #last round
                        chiphertext[i*16:i*16+16] = self.mixColumns(chiphertext[i*16:i*16+16])
                    roundKey = roundKeys[rnd*16:rnd*16+16]
                    chiphertext[i*16:i*16+16] = self.addRoundKey(chiphertext[i*16:i*16+16], roundKey)
            # returns encrypted plaintext as chiphertext
            return bytearray(chiphertext)
        else:
            print "Wrong input parameters given."   # error message
            menu(1)
                  
    # dencryption based on AES Algorithm
    # chiphertext : bytes array
    def decrypt(self,chiphertext,key,mode):
        t = int(ceil(float(len(chiphertext))/16))  # number of iteration of the method
        # A deep copy constructs a new compound object and then, recursively, inserts copies into it of the objects found in the original
        plaintext = deepcopy(chiphertext)   # initialization as a deep copy of chiphertext
        for i in range(0,t):
            nr = len(key)/4 + 6    # number of rounds
            
            # generating round keys based on given key
            roundKeys = self.expandKey(key)
            
            # decryption rounds: encryption steps in reverse order
            for rnd in range(nr,0,-1):
                roundKey = roundKeys[rnd*16:rnd*16+16]
                plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16], roundKey)
                if rnd!=nr :    # last round
                    plaintext[i*16:i*16+16] = self.dec_mixColumns(plaintext[i*16:i*16+16])
                plaintext[i*16:i*16+16] = self.dec_shiftRows(plaintext[i*16:i*16+16])
                plaintext[i*16:i*16+16] = self.dec_subBytes(plaintext[i*16:i*16+16])
                
            # post-round Transformation
            plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16],roundKeys[0:16])
            
            if mode=="CBC" and i!=0:
                plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16],chiphertext[(i-1)*16:(i-1)*16+16])
            if mode=="CBC" and i==0:
                 plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16],self.IV)
        
        # removing blanks filled in encryption step
        for i in range(len(plaintext)-1,-1,-1):
            if plaintext[i]==0:
                plaintext.pop()
            else:
                break
        
        # returns dencrypted chiphertext as plaintext
        return bytearray(plaintext)
    
    # size in bytes
    def generateRandomKey(self,size):
        # The random Key consists of letters, numbers and punctuation
        if size == 16 or size == 24 or size == 32:  # possible sizes
            return bytearray(''.join(random.SystemRandom().choice(string.ascii_letters+string.digits+string.punctuation) for _ in range(16)))
        else:
            print "Wrong input size. Size is given in bytes."
            menu(1)
    
    # password: password given by the user 
    def generatePasswordKey(self,password):
        length = len(password)
        password = bytearray(password)
        if length<=32:
            if length<16:
                for i in range(16-length):
                    password.append("\0")   # fills the blanks
            elif length>16 and length<24:
                for i in range(24-length):
                    password.append("\0")
            elif length>24 and length<32:
                for i in range(32-length):
                    password.append("\0")
            return password
        else:
            print "Password size is bigger than expected."
            menu(1)
            
    # generate encrypted password key for AES-128 with SHA-256 
    def genEncryptedPasswordKey(self,password):
        #generating password key
        password = bytearray(password)
        ##does not need to append '\0', because sha256 outputs fixed length of 256bits##
        # ecrypt password in a fixed 256bit=32byte length using SHA256
        password = binascii.unhexlify(SHA2().sha2(password,256))
        
        return password[0:16]
        
    # saving selected key to a file
    def saveKeytoFile(self,key, filename):
        key = binascii.hexlify(key)     # converting key of type 'str' into type 'hex'
        keyfile = open(filename,'w+')
        keyfile.write(key)
        keyfile.close()
    
    # retrieving Key from a chosen file
    def getKeyfromFile(self,filename):
        try:
            keyfile = open(filename,'r+')
            key = keyfile.readlines()
            keyfile.close()
            # converting key of type 'hex' back into type 'str' and return it as bytearray
            return bytearray(binascii.unhexlify(key[0])) 
        except IOError:
            # error message if the file doesn't exists
            print "Not valid inpupt file "
    
    # a non-linear substitution step where each byte is replaced with another according to Sbox lookup table.
    def subBytes(self, text):
        for i in range(0,16):
            text[i] = self.Sbox[text[i]]
        return text
    
    # same as subBytes but with inverse lookup table
    def dec_subBytes(self, text):
        for i in range(0,16):
            text[i] = self.Ibox[text[i]]
        return text
    
    # shift rows left
    def shiftRows(self, text):
        # text[0:4] does not change
        text[4:8] = text[5],text[6],text[7],text[4]
        text[8:12] = text[10],text[11],text[8],text[9]
        text[12:16] = text[15],text[12],text[13],text[14]
        return text
    
    # shift rows right
    def dec_shiftRows(self, text):
        # text[0:4] does not change
        text[4:8]=text[7],text[4],text[5],text[6]
        text[8:12]=text[10],text[11],text[8],text[9]
        text[12:16]=text[13],text[14],text[15],text[12]
        return text
    
    # combination of columns' bytes using Rijndael linear transformation
    # https://en.wikipedia.org/wiki/Rijndael_mix_columns
    def mixColumns(self, text):
        mixed=range(0,16)
        for i in range(0,4):
            mixed[0+i] = self.mul(2,text[0+i])^self.mul(3,text[4+i])^self.mul(1,text[8+i])^self.mul(1,text[12+i])
            mixed[4+i] = self.mul(1,text[0+i])^self.mul(2,text[4+i])^self.mul(3,text[8+i])^self.mul(1,text[12+i])
            mixed[8+i] = self.mul(1,text[0+i])^self.mul(1,text[4+i])^self.mul(2,text[8+i])^self.mul(3,text[12+i])
            mixed[12+i] = self.mul(3,text[0+i])^self.mul(1,text[4+i])^self.mul(1,text[8+i])^self.mul(2,text[12+i])
        return bytearray(mixed)
    
    # mix columns using inverse mixcolumns' table by Rijndael
    def dec_mixColumns(self,text):
        mixed=range(0,16)
        for i in range(0,4):
            mixed[0+i] = self.mul(14,text[0+i])^self.mul(11,text[4+i])^self.mul(13,text[8+i])^self.mul(9,text[12+i])
            mixed[4+i] = self.mul(9,text[0+i])^self.mul(14,text[4+i])^self.mul(11,text[8+i])^self.mul(13,text[12+i])
            mixed[8+i] = self.mul(13,text[0+i])^self.mul(9,text[4+i])^self.mul(14,text[8+i])^self.mul(11,text[12+i])
            mixed[12+i] = self.mul(11,text[0+i])^self.mul(13,text[4+i])^self.mul(9,text[8+i])^self.mul(14,text[12+i])
        return bytearray(mixed)
    
    # result = text XOR key
    def addRoundKey(self, text, key):
        result=[]
        for i in range(0,16):
            result.append(text[i] ^ key[i])
        return bytearray(result)
        
    # modified key_expand by @fredgj
    def expandKey(self,key):
        nr = (len(key)/4)+6 #rounds
        expanded = deepcopy(key)
        temp = [0]*4
        rcon_iter = 1
        size = len(key)    # key size in bytes
        # 11 keys needed 1 for pre-round tranformation and 10 other for 10 rounds (128bit key)
        size_expanded = (nr+1)*16
        size_current = size
        
        while size_current < size_expanded:
            for i in range(4):
                temp[i] = expanded[(size_current-4)+i]

            if (size_current%size)==0:
                temp = rotate(temp) # Rotation for Rijndael's key schedule
                for i in range(4):
                    temp[i] = self.Sbox[temp[i]]
                
                temp[0] = temp[0]^self.Rcon[rcon_iter]
                rcon_iter += 1
                
            # add an extra Sbox for 256 bit keys
            if (size_current%size)==16 and size==32:
                for i in range(4):
                    temp[i]= self.Sbox[temp[i]]

            for i in range(4):
                expanded.append(expanded[size_current-size]^temp[i])
                size_current += 1
                
        return expanded
        
# Rotates a vector left so [a,b,c,d] => [b,c,d,a]
def rotate(vector):
    tmp = vector[0]

    for i in range(len(vector)-1):
        vector[i] = vector[i+1]

    vector[len(vector)-1] = tmp
    return vector
    
# Miller Rabin primality test
# miller_rabin_test by @andrew-bodine
def miller_rabin_test( a, s, d, n ):
    atop = pow( a, d, n )
    if atop == 1:
        return True
    for i in xrange( s - 1 ):
        if atop == n - 1:
            return True
        atop = ( atop * atop ) % n
    return atop == n - 1
    
# miller_rabin by @andrew-bodine
def miller_rabin( n ):
    confidence = 20     # primality test accuracy
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1
    for i in range( confidence ):
        a = 0
        while a == 0:
            a = random.randrange( n )
        if not miller_rabin_test( a, s, d, n ):
            return False
    return True

# Class RSA Cryptosystem: 1) Generating a key pair 2) encryption/decryption
class RSA(object):
    
    # Euclid's Greatest Common Divisor
    def gcd(self,a,b):
        if a < b:
            a, b = b, a
        while b != 0:
            a, b = b, a % b
        return a
        
    # Extended Euclidean Algorithm
    # return (g, x, y) a*x + b*y = gcd(x, y)
    # egcd by https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    def eea(self,a,b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, x, y = self.eea(b % a, a)
            return (g, y - (b // a) * x, x)
    
    # inverse modulo
    # x = inversemod(b) mod n, (x * b) % n == 1
    # mulinv by https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    def inversemod(self,b,n):
        g, x, _ = self.eea(b,n)
        if g == 1:
            return x % n
        else:
            return None
    
    # generating public key and private key pairs
    # Steps followed from https://simple.wikipedia.org/wiki/RSA_(algorithm) and
    # https://www.tutorialspoint.com/cryptography/public_key_encryption.htm
    # modulus size nsize in bits
    def generateKeyPair(self,nsize):
        if nsize >=512:
            # generating 2 large prime numbers of nsize/2 size
            while 1:
                p = random.getrandbits(int(ceil(float(nsize)/2)))
                if miller_rabin(p):
                    break                  
            while 1:
                q = random.getrandbits(int(ceil(float(nsize)/2)))
                if miller_rabin(q):
                    break
            # Generate public key pair (n,e)
            # calulating modulus n of nsize size
            n = p*q
            # calulating phi using Euler's totient function
            phi = (p-1)*(q-1)     
            # Find Derived Number e, where 1<e<phi and e,phi are coprimes
            e = random.randrange(1,phi)
            while self.gcd(e,phi)!=1:   # checks if e,phi are coprimes
                e = random.randrange(1,phi)      
            # Genrate private key pair (n,d)
            d = self.inversemod(e,phi)
            # return modulus, public key exponent, private key exponent
            return n,e,d            
        else:
            print "Wrong given size"
            menu(2)
      
    def saveRSAKeys(self,pub,sec,filename):
        keyfilePair = open(filename + ".pair",'w+')
        pair = pub+" "+sec
        keyfilePair.write(pair)
        keyfilePair.close()
        keyfilePub = open(filename + ".pub",'w+')
        keyfilePub.write(pub)
        keyfilePub.close()
        keyfileSec = open(filename + ".sec",'w+')
        keyfileSec.write(sec)
        keyfileSec.close()
    
    def getRSAKeys(self,filename):
        try:
            n = None
            e = None
            d = None
            
            if (filename.split(".")[1]=="pair"):
                keyfilePair = open(filename,'r+')
                pair = keyfilePair.read()
                public = pair.split(" ) Private Key: ( ")[0]
                e = public.split(" , ")[1]
                private = pair.split(" ) Private Key: ( ")[1]
                n = private.split(" , ")[0]
                temp = private.split(" , ")[1]
                d = temp.split(" )")[0]
                keyfilePair.close()
            elif (filename.split(".")[1]=="pub"):
                keyfilePub = open(filename,'r+')
                public = keyfilePub.read()
                mod = public.split(" , ")[0]
                exp = public.split(" , ")[1]
                n = mod.split("Public Key: ( ")[1]
                e = exp.split(" )")[0]
                keyfilePub.close()
            elif (filename.split(".")[1]=="sec"):
                keyfileSec = open(filename,'r+')
                private = keyfileSec.read()
                mod = private.split(" , ")[0] 
                dexp = private.split(" , ")[1]
                n = mod.split("Private Key: ( ")[1]
                d = dexp.split(" )")[0]
                    
            return n,e,d
        except IOError:
            # error message if the file doesn't exists
            print "Not valid inpupt file "
    

    # RSA encryption :  C = P^e % n
    def encrypt(self, plaintext, n, e):     
        C = []
        for p in plaintext:
            C.append(pow(ord(p),e,n))      
        return C
    
    # RSA decryption :  P = C^d % n
    def decrypt(self, chiphertext, n, d):     
        P = ''        
        for c in chiphertext:
            P += chr(pow(c,d,n))              
        return P
        
# right rotate n times
def rightrotate(w, n):
    return w[-n:]+w[:-n]

# right shift, fill with zeros
def rightshift(w, n):
    return '0'*n+w[:-n]

# xor 2 same bit numbers
def xor(w1,w2):
    wr = bin(int(w1,2)^int(w2,2)).replace('b','')
    return (len(w1)-len(wr))*'0'+wr

# add 2 32/64 bit numbers (fixes the length to 32bit :/ )
def add(w1, w2, bits):
    
    sn = int(w1,2)
    on = int(w2,2)
    wr = bin((sn + on)%(2**len(w1)))    #sum in modulo 2^32
    wr = wr.replace('0b','')
    if bits==32:
        return (32-len(wr))*'0'+ wr
    elif bits==64:
        return (64-len(wr))*'0'+ wr

# hex to bin of 32/64 bit length 
def hextobin(hx,bits):
    bn = bin(int(hx))
    bn = bn.replace('0b','')
    if bits==32:    
        return (32-len(bn))*'0'+bn
    elif bits==64:
        return (64-len(bn))*'0'+bn

# bitwise and 2 binary of same bit length 
def bitand(a,b):
    result = ''
    for i in range(len(a)):
        result += str(int(a[i],2) and int(b[i],2))    
    return result
    
# bitwise not a binary of any bit length 
def bitnot(b):
    result = ''
    for i in range(len(b)):
        result += str(int(not int(b[i])))
        
    return result
    
# Secure Hash Function (SHA)
# Steps followed by https://en.wikipedia.org/wiki/SHA-2
class SHA2(object):

    def binarypadding(self,data,chunks):
        if chunks==512:
            length = 8*len(data)  # length in bits
            # string to binary
            data = bin(int(binascii.hexlify(data),16)).replace('b','')
            # add '1' at the end
            data = data + "1"
            # zero padding
            for i in range(512):
                if (len(data)%512)!=448:
                    data +="0"
            # add a 64bit number of the original size at the end
            length = bin(length).replace('b','')
            for l in range(64):
                if len(length)%64!=0:
                    length = "0"+ length
            data += length
            
        elif chunks==1024:
            length = 8*len(data)  # length in bits
            # string to binary
            data = bin(int(binascii.hexlify(data),16)).replace('b','')
            # add '1' at the end
            data = data + "1"
            # zero padding
            for i in range(1024):
                if (len(data)%1024)!=896:
                    data +="0"
                    
            # add a 128 bit number of the original size at the end
            length = bin(length).replace('b','')
            for l in range(128):
                if len(length)%128!=0:
                    length = "0"+ length
            data += length
            
        return data
        
    # sha-2 implementation for 224, 256, 384 and 512 bits output
    def sha2(self, data, numbits):
        if numbits==256 or numbits==224:
            if numbits==256:
                # initialize hash values for sha256
                h0 = hextobin(0x6a09e667,32)
                h1 = hextobin(0xbb67ae85,32)
                h2 = hextobin(0x3c6ef372,32)
                h3 = hextobin(0xa54ff53a,32)
                h4 = hextobin(0x510e527f,32)
                h5 = hextobin(0x9b05688c,32)
                h6 = hextobin(0x1f83d9ab,32)
                h7 = hextobin(0x5be0cd19,32)
            elif numbits==224:
                # initialize hash values for sha224
                h0 = hextobin(0xc1059ed8,32)
                h1 = hextobin(0x367cd507,32)
                h2 = hextobin(0x3070dd17,32)
                h3 = hextobin(0xf70e5939,32)
                h4 = hextobin(0xffc00b31,32)
                h5 = hextobin(0x68581511,32)
                h6 = hextobin(0x64f98fa7,32)
                h7 = hextobin(0xbefa4fa4,32)
                
            # initialize array of round constants:
            k = [hextobin(i,32) for i in 
                [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]]
    
            # pre-processing
            data = self.binarypadding(data,512)
            
            # break message in chunks of 512 bits
            for i in range(len(data)/512):
                chunk= data[i*512:i*512+512]
                # create a 64-entry message schedule array w[0..63] of 32-bit words
                # copy chunk into first 16 words w[0..15] of the message schedule array            
                w = []
                for i in range(512/32):
                    w += chunk[i*32:i*32+32],
                # fill w[16..63] with 32bit zeros
                for i in range(16,64):
                    w += '0'*32,
                #  Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
                for i in range(16,64):
                    s0 = xor(rightrotate(w[i-15],7),xor(rightrotate(w[i-15],18),rightshift(w[i-15],3)))
                    s1 = xor(rightrotate(w[i-2],17),xor(rightrotate(w[i-2],19),rightshift(w[i-2],10)))
                    w[i] = add(w[i-16],add(s0,add(w[i-7],s1,32),32),32)
                # Initialize working variables to current hash value:
                a = h0
                b = h1
                c = h2
                d = h3
                e = h4
                f = h5
                g = h6
                h = h7
                
                # Compression function main loop:
                for i in range(64):
                    S1 = xor(rightrotate(e,6),xor(rightrotate(e,11),rightrotate(e, 25)))
                    ch = xor(bitand(e,f),bitand(bitnot(e),g))
                    temp1 = add(h,add(S1,add(ch,add(k[i],w[i],32),32),32),32)
                    S0 = xor(rightrotate(a,2),xor(rightrotate(a,13),rightrotate(a, 22)))
                    maj = xor(bitand(a,b), xor(bitand(a,c), bitand(b,c)))
                    temp2 = add(S0, maj,32)
                    
                    h = g
                    g = f
                    f = e
                    e = add(d,temp1,32)
                    d = c
                    c = b
                    b = a
                    a = add(temp1,temp2,32)    
                # Add the compressed chunk to the current hash value:
                h0 = add(h0,a,32)
                h1 = add(h1,b,32)
                h2 = add(h2,c,32)
                h3 = add(h3,d,32)
                h4 = add(h4,e,32)
                h5 = add(h5,f,32)
                h6 = add(h6,g,32)
                h7 = add(h7,h,32)
            
            # Produce the final hash value (big-endian):
            if numbits==256:
                digest = h0+h1+h2+h3+h4+h5+h6+h7
            elif numbits==224:
               digest = h0+h1+h2+h3+h4+h5+h6
               
            result = ''
            for i in range(len(digest)/8):
                result += chr(int(digest[i*8:i*8+8],2))
            
            return binascii.hexlify(result)
            
        elif numbits==512 or numbits==384:
            # the initial hash values and round constants are extended to 64 bits
            if numbits==512:
                # initialize hash values for sha512
                h0 = hextobin(0x6a09e667f3bcc908,64)
                h1 = hextobin(0xbb67ae8584caa73b,64)
                h2 = hextobin(0x3c6ef372fe94f82b,64)
                h3 = hextobin(0xa54ff53a5f1d36f1,64)
                h4 = hextobin(0x510e527fade682d1,64)
                h5 = hextobin(0x9b05688c2b3e6c1f,64)
                h6 = hextobin(0x1f83d9abfb41bd6b,64)
                h7 = hextobin(0x5be0cd19137e2179,64)
            elif numbits==384:
                # initialize hash values for sha224
                h0 = hextobin(0xcbbb9d5dc1059ed8,64)
                h1 = hextobin(0x629a292a367cd507,64)
                h2 = hextobin(0x9159015a3070dd17,64)
                h3 = hextobin(0x152fecd8f70e5939,64)
                h4 = hextobin(0x67332667ffc00b31,64)
                h5 = hextobin(0x8eb44a8768581511,64)
                h6 = hextobin(0xdb0c2e0d64f98fa7,64)
                h7 = hextobin(0x47b5481dbefa4fa4,64)
            
            # initialize array of round constants:   
            k = [hextobin(i,64) for i in
                [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
                 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
                 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
                 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
                 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
                 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
                 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
                 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
                 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
                 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
                 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
                 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
                 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
                 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
                 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
                 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]]
            
            # pre-processing
            data = self.binarypadding(data,1024)
            
            # break message in chunks of 1024 bits
            for i in range(len(data)/1024):
                chunk= data[i*1024:i*1024+1024]
                
                # create a 80-entry message schedule array w[0..79] of 64-bit words
                # copy chunk into first 16 words w[0..15] of the message schedule array            
                w = []
                for i in range(1024/64):
                    w += chunk[i*64:i*64+64],

                # fill w[16..79] with 64 bit zeros
                for i in range(16,80):
                    w += '0'*64,
                    
                #  Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
                for i in range(16,80):
                    s0 = xor(rightrotate(w[i-15],1),xor(rightrotate(w[i-15],8),rightshift(w[i-15],7)))
                    s1 = xor(rightrotate(w[i-2],19),xor(rightrotate(w[i-2],61),rightshift(w[i-2],6)))
                    w[i] = add(w[i-16],add(s0,add(w[i-7],s1,64),64),64)
                    
                # Initialize working variables to current hash value:
                a = h0
                b = h1
                c = h2
                d = h3
                e = h4
                f = h5
                g = h6
                h = h7
                
                # Compression function main loop:
                for i in range(80):
                    S1 = xor(rightrotate(e,14),xor(rightrotate(e,18),rightrotate(e, 41)))
                    ch = xor(bitand(e,f),bitand(bitnot(e),g))
                    temp1 = add(h,add(S1,add(ch,add(k[i],w[i],64),64),64),64)
                    S0 = xor(rightrotate(a,28),xor(rightrotate(a,34),rightrotate(a, 39)))
                    maj = xor(bitand(a,b), xor(bitand(a,c), bitand(b,c)))
                    temp2 = add(S0, maj,64)
                    
                    h = g
                    g = f
                    f = e
                    e = add(d,temp1,64)
                    d = c
                    c = b
                    b = a
                    a = add(temp1,temp2,64)   
                    
                # Add the compressed chunk to the current hash value:
                h0 = add(h0,a,64)
                h1 = add(h1,b,64)
                h2 = add(h2,c,64)
                h3 = add(h3,d,64)
                h4 = add(h4,e,64)
                h5 = add(h5,f,64)
                h6 = add(h6,g,64)
                h7 = add(h7,h,64)
                
            # Produce the final hash value (big-endian):
            if numbits==512:
                digest = h0+h1+h2+h3+h4+h5+h6+h7
            elif numbits==384:
               digest = h0+h1+h2+h3+h4+h5
               
            result = ''
            for i in range(len(digest)/8):
                result += chr(int(digest[i*8:i*8+8],2))
                
            return binascii.hexlify(result)
        else :
            print "Not a valid SHA-2 function"
            menu(3)
            

# signing message with RSA generated private key
def sign(message,n,d):
    rsa = RSA()     # assigning RSA instanse
    sha = SHA2()    # assigning SHA2 instanse
    # Step 1 : hashing the given message with RSA256
    hashed_message = sha.sha2(message,256)
    # Step 2 : ecrypt hashed message using private key with RSA encryption algorithm
    signature = rsa.encrypt(hashed_message,n,d)
    return signature

def verify(message, signature, n, e):
    rsa = RSA()     # assigning RSA instanse
    sha = SHA2()    # assigning SHA2 instanse
    # Step 1: decrypt signature
    signature = rsa.decrypt(signature, n, e)
    # Step 2: Hash original message
    hashed_message = sha.sha2(message,256)
    # Step 3: Compare
    if hashed_message == signature:
        return True
    else:
        return False

def menu(n):
    aes = AES()     # assigning AES instanse
    rsa = RSA()     # assigning RSA instanse
    sha = SHA2()    # assigning SHA2 instanse
    
    print "--------Demo--------"
    print "--------AES--------"
    print "Generate Key, Size=32"
    demokey = aes.generateRandomKey(32)
    print "**AES Encryption**"
    demotext =  bytearray("Edward Snowden")
    original = deepcopy(demotext)
    demomode = "ECB"
    print "Inputs :"
    print "Plaintext = \""+demotext+"\""
    print "Key = \""+demokey+"\""
    print type(demokey)
    print "Mode = \""+demomode+"\""
    print ""
    demochipher = aes.encrypt(demotext,demokey,demomode)
    print "Chiphertext = \""+demochipher+"\""
    print ""
    print "**AES Decryption**"
    print "Inputs :"
    print "Chiphertext = \""+demochipher+"\""
    print "Key = \""+demokey+"\""
    print "Mode = \""+demomode+"\""
    demodecrypted = aes.decrypt(demochipher,demokey,demomode)
    print ""
    print "Decrypted Chipher = \""+demodecrypted+"\""
    print "Success = ",demodecrypted==original
    print ""
    print ""
    print "--------RSA--------"
    print "Generate Key Pair"
    print "Inputs :"
    print "Modulus size = 512 bits"
    demon,demoe,demod = rsa.generateKeyPair(512)
    print "Modulus = \""+str(demon)+"\""
    print "Public Exponent = \""+str(demoe)+"\""
    print "Private Exponent = \""+str(demod)+"\""
    print ""
    print "**RSA Encryption**"
    demotext = "Edward Snowden"
    print "Inputs :"
    print "Plaintext = \""+demotext+"\""
    print "Modulus = \""+str(demon)+"\""
    print "Public Exponent = \""+str(demoe)+"\""
    demochipher = rsa.encrypt(demotext,demon,demoe)
    print ""
    print "Chiphertext = \""+str(demochipher)+"\""
    print ""
    print "**RSA Decryption**"
    print "Inputs :"
    print "Chiphertext = \""+str(demochipher)+"\""
    print "Modulus = \""+str(demon)+"\""
    print "Private Exponent = \""+str(demod)+"\""
    demodecrypted = rsa.decrypt(demochipher,demon,demod)
    print ""
    print "Chiphertext = \""+str(demodecrypted)+"\""
    print "Success = ",demodecrypted==demotext
    print ""
    print ""
    print "--------SHA-2--------"
    demomessage = "Edward Snowden"
    print "**SHA-256 Encryption**"
    print "Inputs :"
    print "Message = \""+demomessage+"\""
    demohashed = sha.sha2(demomessage,256)
    print ""
    print "Hashed message =\""+demohashed+"\""
    print ""
    print ""
    print "--------Sign/Verify--------"
    print "**Digital Signature**"
    print "Inputs :"
    print "Message =\""+demomessage+"\""
    print "Modulus = \""+str(demon)+"\""
    print "Private Exponent = \""+str(demod)+"\""
    demosign = sign(demomessage,demon,demod)
    print ""
    print "Signature = \""+str(demosign)+"\""
    print ""
    print "**Digital Verification**"
    print "Inputs :"
    print "Message =\""+demomessage+"\""
    print "Signature = \""+str(demosign)+"\""
    print "Modulus = \""+str(demon)+"\""
    print "Public Exponent = \""+str(demoe)+"\""
    demoverified = verify(demomessage,demosign,demon,demoe)
    print ""
    if demoverified:
        print "Verification Successful!"
    elif not demoverified:
        print "Verification Failed... :("
    print ""
    print ""
    print "--------AES-128 with SHA-256--------"
    demopassword = "Edward Snowden"
    print "Generate key"
    print "Inputs :"
    print "Password \""+demopassword+"\""
    demoenckey = aes.genEncryptedPasswordKey(demopassword)
    print ""
    print "Encrypted key =\""+demoenckey+"\""
    print ""
    print "Save key"
    demofilename = "demoenckey"
    print "Inputs :"
    print "Filename = \"demoenckey\""
    aes.saveKeytoFile(demoenckey,demofilename)
    print "Save at \"demoenckey\""
    print ""
    print "***For more flexibility run the other menu options!***"
    print "-------------------"  

# main function
def main():
    menu()
if __name__ == "__main__":
    main()
