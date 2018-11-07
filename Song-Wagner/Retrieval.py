import os
from Crypto.Cipher import DES
import binascii
import hmac
import csv
from Crypto import Random

k_1,k_2 = None, None
with open('keysandsi.csv', newline='') as File:  
    reader = csv.reader(File,delimiter=',')
    data = [row for row in reader]
    k_1 = data[0][0]
    k_2 = data[0][1]

    print (k_1)
    print (k_2)

    S_i = data[1][0]
    print (S_i)
    # for row in reader:
    #     # print(row)
    #     k_1 = row[0][0]
    #     # k_2 = row[1]
    #     print (k_1)
    #     # print (k_2)
