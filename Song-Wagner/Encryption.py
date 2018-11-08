#encryption
import os
from Crypto.Cipher import DES
import binascii
import hmac
import csv
from Crypto import Random

# m = 8
# n = 16
# L_i = n-m = 8

a_bc = os.urandom(32)							# Generated 16 byte Plain Text Block
print ("full PT",a_bc)
a_hex=a_bc.hex()
w_i = a_bc.hex()[0:32]							# w_i of length n 
print ("first 16 bytes ", w_i)
w_i_bytecode = bytes.fromhex(w_i)
print ("first 16 bytes ", w_i_bytecode)

#Step 2
k_2 = os.urandom(8)									#Getting the hash working
k_1 = os.urandom(8)


##store k1 and k2 in a csv file
keys = [k_1.hex(),k_2.hex()]
myFile = open('keysandsi.csv', 'w', newline='')
with myFile:
    writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(keys)

C_T = ""
iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'



#STEP 1, Partition to find W_I    
print ("\n")
for plain_fragment in ([a_hex[i:i+32] for i in range(0, len(a_hex), 32)]):
    print("W_I",plain_fragment)

#STEP 2, Got Plaintext fragment and key now. Start finding X_i

    des = DES.new(k_2, DES.MODE_ECB)
    X_i = des.encrypt(bytes.fromhex(plain_fragment))
    print("X_I",X_i)
    print("X_I_HEX", X_i.hex())

#STEP 3, Found L_I    
    L_i = X_i.hex()[0:16]
    print("L_I_HEX",L_i)

#STEP 4, Encrypt L_i with k_1
    des = DES.new(k_1, DES.MODE_CBC,iv)
    k_i = des.encrypt(bytes.fromhex(L_i))

#STEP 5, Find S_i
    s_i = os.urandom(8)    
    s_i_entry = [s_i.hex()]
    myFile = open('keysandsi.csv', 'a', newline='')
    with myFile:
        writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(s_i_entry)


#Step 6, Find FKISI
    F_k = DES.new(k_i, DES.MODE_CBC,iv)
    F_k_i_s_i = F_k.encrypt(s_i)

    print("F_k_i_s_i", F_k_i_s_i.hex())


    T_i = s_i.hex() + F_k_i_s_i.hex()
    print ("T_I", T_i)
    
    X_i = X_i.hex()	
    C_i = hex(int(X_i, 16) ^ int(T_i, 16))[2:]
    print ("C_i",C_i)

    print("\n")
    print("Starting Search")


#Search PART
#Step 1: Finding X_J
    des = DES.new(k_2, DES.MODE_ECB)
    X_j = des.encrypt(bytes.fromhex(plain_fragment))
	
    L_j = X_j.hex()[0:16]
    print("L_J_HEX",L_j)

    des = DES.new(k_1, DES.MODE_CBC,iv)
    k_j = des.encrypt(bytes.fromhex(L_j))

    print("Alice sends X_j and K_J to bob")
    C_p = C_i

#Bob, for each C_p
    X_j = X_j.hex()	
    T_p = hex(int(X_j, 16) ^ int(C_p, 16))[2:]

    print ("T_p",T_p)
    S_p = T_p[0:16]
    S_p_bar = T_p[16:32]

#Find FKjSp
    F_k = DES.new(k_j, DES.MODE_CBC,iv)
    F_k_j_s_p = F_k.encrypt(bytes.fromhex(S_p))   
 
    print ("S_p_bar from calc",S_p_bar)
    print ("S_p_bar from func",F_k_j_s_p.hex())
    print("\n")


    ###First hash function to generate k_i
    ''''
    ###Compute hash from DES in CBC mode
    f_k = DES.new(k_1, DES.MODE_CBC,iv)
    #below two lines can be used to change from DES to SHA-1 or MD-5 with HMAC
    #f_k = hmac.new(k_1, L_i, hashlib.sha1)
    #f_k.update(L_i)
    #print ("Key", binascii.hexlify(k_1))
    #print ("First PT Li ",binascii.hexlify(L_i))
    k_i = f_k.encrypt(L_i)
    print ("k_i the first CT ", binascii.hexlify(k_i))
    

    ###with k_i as the key, generate F_k(S_i)
    print ("Second PT ", binascii.hexlify(s_i))
    #below two lines can be used to change from DES to SHA-1 or MD-5 with HMAC
    #F_k = hmac.new(k_i, s_i, hashlib.sha1)
    #F_k_i_s_i = binascii.hexlify(F_k.encrypt(s_i))
    F_k = DES.new(k_i, DES.MODE_CBC,iv)
    print ("second key ", binascii.hexlify(k_i))
    F_k_i_s_i = F_k.encrypt(s_i)
    print ("second encryption ", binascii.hexlify(F_k_i_s_i))
    print ()
    
    ##Concatenation of si and fk(si) to get Ti
    T_i = s_i + F_k_i_s_i
    
    ##Perform XOR between Xi and Ti
    
    #C_i = binascii.unhexlify(C_i)
    C_i = bytes.fromhex(C_i[2:])
    print ("Final Ci", C_i)

    C_T = C_T + C_i.hex()
    
print ("Cipher text obtained at the end  ", C_T)


    Ciphers = [C_i]

    myFile = open('c_i.csv', 'a', newline='')
    with myFile:
        writer = csv.writer(myFile, delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(Ciphers)   

# keys = [k_1.hex(),k_2.hex()]
# myFile = open('keysandsi.csv', 'w', newline='')
# with myFile:
#     writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
#     writer.writerow(keys)


'''