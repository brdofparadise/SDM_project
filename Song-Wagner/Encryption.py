import os
from Crypto.Cipher import DES
import binascii
import hmac
import csv
from Crypto import Random

a = os.urandom(32)							# Generated 16 byte Plain Text Block
print ("full PT",a)
print ("first 8 bytes ", a[0:8])
#b = binascii.hexlify(a)

#b = hex(a)
#b= bytes(a, "hex")
#b = a									# Conversions
#c = int(hex(a), 16)						# Conversions
#d = bin(int(hex(a), 16))					# Conversions

#Step 2
k_2 = os.urandom(8)									#Getting the hash working
k_1 = os.urandom(8)

##store k1 and k2 in a csv file
#keys = [binascii.hexlify(k_1),binascii.hexlify(k_2)]
keys = [k_1.hex(),k_2.hex()]
myFile = open('keysandsi.csv', 'w', newline='')
with myFile:
    writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(keys)

#s_i = os.urandom(8)
    
for plain_fragment in ([a[i:i+16] for i in range(0, len(a), 16)]):
    s_i = os.urandom(8)    
    s_i_entry = [s_i.hex()]
    myFile = open('keysandsi.csv', 'a', newline='')
    with myFile:
        writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(s_i_entry)

    des = DES.new(k_2, DES.MODE_ECB)
    cipher_fragment = des.encrypt(plain_fragment)
    #print (len(cipher_fragment))
    L_i = cipher_fragment[0:int(len(a)/2)]
    #k_i = m.update(L_i) 
    decrypt_fragment = des.decrypt(cipher_fragment)

    #print (decrypt_fragment)
    
    ###First hash function to generate k_i
    
    ###Compute hash from DES in CBC mode
    iv = Random.new().read(DES.block_size)
    print ("iv", binascii.hexlify(iv))
    f_k = DES.new(k_1, DES.MODE_CBC,iv)
    #below two lines can be used to change from DES to SHA-1 or MD-5 with HMAC
    #f_k = hmac.new(k_1, L_i, hashlib.sha1)
    #f_k.update(L_i)
    print ("Key", binascii.hexlify(k_1))
    print ("First PT Li ",binascii.hexlify(L_i))
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
    cipher_fragment = cipher_fragment.hex()	
    T_i = T_i.hex()	
    C_i = hex(int(cipher_fragment, 16) ^ int(T_i, 16))
    print ("Final Ci", C_i)
   
#Read the keys from csv file
#with open('example2.csv', newline='') as File:  
#    reader = csv.reader(File,delimiter=',')
#    for row in reader:
#        print(row)