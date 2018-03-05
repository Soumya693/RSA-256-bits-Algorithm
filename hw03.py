import PrimeGenerator
from BitVector import *
import textwrap
import os
import codecs

e = 65537
pg = 0
qg = 0
ng = 0

try:                #exception handling: To make sure the files existing earlier are removed before creating the files
    os.remove("output.txt")
    os.remove("decrypted.txt")
except:
    pass

def gen_keys():
    generator = PrimeGenerator.PrimeGenerator( bits = 128, debug = 0, emod = 65537)
    return generator.findPrime()
    
    
    #print ("{0:b}".format(p))
    #print ("{0:b}".format(q))
    #c=len("{0:b}".format(p))
    #print(c)

def gcd(a,b):
    
    x = max(a,b)
    y = min(a,b)
    if x==0:
        return y
    if y==0:
        return x
    r = x%y
    if r==0:
        return y  
    else:
        return gcd(y,r)
        
def string2bin8(string):    # to convert a text to binary bits(8) and join them as a single binary string
    w = ''
    w = ''.join(format(ord(x), 'b').zfill(8) for x in string)
    return w



def append_newline(con,l): # if the length of the message is not a multiple of 16 then append it with newline characters, returns the content with appended text
    if l%16 == 0:
        print("yes")
    else:
        b = int(l%16)
        c = 16 - b
        con + c*'\n'
    return con



def prepend_bits256(block): # To prepend each block-128 bits to 256 bits
    db = []
    for b in block:
        db.append(b.rjust(256,'0'))
    return db

def bin_2string(bin_string):
    return int(bin_string,2)

 
        
def coprime(a,b):
    g= gcd(a,b)
    if g == 1:
        return True
    else:
        return False
    
def cipher(m,x,y):
    a = m**x
    c= a%y
    return c

def dec2bin(ciph):    #converting the obatained cipher number into binary - each block returntype : str
    return bin(ciph)[2:].zfill(256)




#fe= open("encrypted.txt","x+")
def write_encrypt_file(ciph_blocks, fe):        #encrypting each block(containing 8 bits) into unicode characters and writing in the file
    print("encrypting blocks and writing in output.txt")
    for bb in ciph_blocks:
        #print(bb) 
        #print(ch)
        ch = str(chr(int(bb,2)))
        ch = ch.encode("latin1")
        fe.write(ch)

        
def write_decrypt_file(mes_blocks, fd):
    print("decrypting blocks and writing in decrypted.txt")
    for d in mes_blocks:
        ch = chr(int(d,2))
        fd.write(ch)
    

def find_d_instring(a,b):
    s = BitVector(intVal = a)
    mod = BitVector(intVal = b)
    d_bits = BitVector.multiplicative_inverse(s,mod)
    return int(str(d_bits),2)

def decrypt(c,d,n):
    return pow(c,d,n)


def check_keys(p,q,e): # To check the conditions for p and q
    f1= False
    f2= False
    f3 = False
    if coprime(p-1,e):
        f1 = True
    if coprime(q-1,e):
        f2 = True
    if p!=q:
        f3 = True

    if f1 and f2 and f3:
        return True
    else:
        return False

def encryption(e):    # encryption method
    print("encrypting contents of the file")
    global ng
    global pg
    global qg
    keys_found = False
    while(not keys_found):
        p = gen_keys()
        q = gen_keys()
        pg = p
        qg = q
        if check_keys(p,q,e):        #breaking the loop when all the three conditions for generating p and q
            keys_found = True
    n = p*q
    
    bin_n = bin(n)[2:].zfill(256)
    str_n = bin_2string(bin_n)
    ng = str_n
    f=open("message.txt", "r")
    if f.mode == 'r':
        con =f.read()
        f.close()
    l = len(con)
    adjusted_con = string2bin8(append_newline(con,l))
    blocks = textwrap.wrap(adjusted_con, 128)
    blocks_256 = prepend_bits256(blocks)
    fe= open("output.txt","wb+")
    for i in blocks_256:
        #print(i)
        m = bin_2string(i)
        #print(m)
        c  = cipher(m,e,str_n)
        #print(c)
        ciph_bin = dec2bin(c)
        #print((ciph_bin))
        ciph_blocks = textwrap.wrap(ciph_bin, 8) # creating chunks[list] of 8 bits binary string from dec2bin() : single block only
        #print(ciph_blocks)
        write_encrypt_file(ciph_blocks, fe)
    fe.close()
        
    
    
def decryption(pg, qg, e, ng):     #Decrypting the encrypted text stored in output.txt
    print("Decrypting the encrypted file")
    phi = (pg-1)*(qg-1)
    f =  open('output.txt', 'rb')
    if f.mode == 'rb':
        e_con =f.read()
        f.close()
    #l = len(e_con)
    
        #print(i)
    bin_con = ''.join(bin(i)[2:].zfill(8) for i in e_con )
    #print(bin_con)
    #print(len(bin_con))
    #print(e_con)
    #bin_con = string2bin8(e_con)
    blocks = textwrap.wrap(bin_con, 256)
    d = find_d_instring(e, phi)
    fd = open('decrypted.txt', 'w+')
    for i in blocks:
        #print(i)
        c = bin_2string(i)
        #print(c)
        m = decrypt(c,d,ng)
        #print(m)
        m_bin = dec2bin(m)
        #print(m_bin)
        m_bin = m_bin.lstrip('0')
        l = len(m_bin)
        if l/8!=0:  # checking if the size of binary is a multiple of 8 after unpadding zeros, and converted into a multiple of 8
            r = l%8
            p = 8-r
        l = l+p
        m_bin = m_bin.zfill(l)  # zero padding after correcting the length of the each binary block
        mes_blocks = textwrap.wrap(m_bin,8)
        write_decrypt_file(mes_blocks, fd)
    fd.close()


encryption(e)
print("Encryption completed!!!")
decryption(pg, qg, e, ng)
        
    
    
    
    


    
    
    






    
    
    
    
    

