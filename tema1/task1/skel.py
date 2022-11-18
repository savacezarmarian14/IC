from pwn import *
import base64 as b64
from time import sleep

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
LOCAL = False # Local means that you run binary directly
if LOCAL:
     # Complete this if you want to test locally
     r = process(argv=["python3","/home/cezar/Desktop/Facultate/Anul 4/IC/tema1/task1/server.py"])
else:
     r = remote("141.85.224.117", 1337)  # Complete this if changed
def read_options():
    """Reads server options menu."""
    r.readuntil(b"Input:")
def get_token():
    """Gets anonymous token as bytearray."""
    read_options()
    r.sendline(b"1")
    token = r.readline()[:-1]
    return b64.b64decode(token)

def login(tag):
    """Expects bytearray. Sends base64 tag."""
    r.readline()
    read_options()
    r.sendline(b"2")
    # sleep(0.01) # Uncoment this if server rate-limits you too hard
    r.sendline(b64.b64encode(tag))
    r.readuntil(b"Token:")
    response = r.readline().strip()
    return response

def find_SPB(token):
    # Pentru a afla SPB voi urma pasii:
    #   1.1 Pentru a afla index-ul de inceput al SPB-ului voi schimba tokenul 
    #      generand un nou token format din b'X' * [1..] si 
    #      ce mai ramane din token pana cand formeaza un nou token
    #      de aceasi lungime
    #   1.2 Voi trimite noul token (fake_token) ca input pt login pana cand se va
    #       schimba measjul de eroare 
    #   2. Pentru a afla index-ul de final al SPB-ului voi aplica aceasi metoda dar 
    #      de data asta plecand cu b'X' de la finalul token-ului
    #     
    #      \/--- b'X'                   b'X' ---\/
    #  ---------------------------------------------
    #  |    MESSAGE    |    SPB       |  Integrity |
    #  ---------------------------------------------
    for index in range(1, len(token)):
        fake_token = b'X'*index + token[index:]
        if login(fake_token) == b'Wrong server secret!':
            break
    start_SPB = index - 1

    for index in range(len(token) - 1, 0, -1):
        fake_token = token[:index] + b'X' * (len(token)-index)
        if login(fake_token) == b'Wrong server secret!':
            break
    end_SPB = index + 1
    return token[:start_SPB], token[start_SPB:end_SPB]

def find_user_encryption(chiper):
    GUEST_NAME = b"Anonymous"
    TARGET = b'Ephvuln'
    random_thing = byte_xor(chiper, GUEST_NAME)
    return byte_xor(TARGET, random_thing)

def main():
    token = get_token()
    chiper, SPB = find_SPB(token)
    target_user = find_user_encryption(chiper)
    # BRUTE FORCE
    for i in range(255):
        new_token = target_user + SPB + i.to_bytes(1, 'big')
        res = login(new_token)
        if res != b'Failed integrity check!':
            print("====> " + str(res)[2:-1] + " <====") # 2:-1 ca sa scap de "b'" si " ' "
            break
    r.close()

    
    
    
    



if __name__ == "__main__":
    main()
    
