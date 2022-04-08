import math
import time
import random
#import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://10.92.52.175:5000/'
stuID = 26853

curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator


IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,
                 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def IKRegReq(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if not response.ok: print(response.json())


def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())


def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)
    if((response.ok) == False):
        print(response.json())
    else:
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']


def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)
    if((response.ok) == False): print(response.json())


# <------------------------------------------- PHASE 1 ------------------------------------------->
def EncodeInteger(num):
    return num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')


def generate_key(base, order):
    secret = Random.new().read(int(math.log(order, 2)))
    secret = (int.from_bytes(secret, byteorder='big') % (order - 2)) + 1
    public = secret * base
    return secret, public


def get_public(secret, base):
    return secret * base


def hash(point, message, order):
    x = point.x % order
    x_encoded = EncodeInteger(x)

    token_encoded = x_encoded + message

    h = SHA3_256.new(token_encoded).digest()
    h = int.from_bytes(h, byteorder='big') % order

    return h


def sign(message, base, order, secret):
    k = Random.new().read(int(math.log(n, 2)))
    k = (int.from_bytes(k, byteorder='big') % (order - 2)) + 1
    R = k * base

    h = hash(R, message, order)
    s = (k - secret * h) % order

    return h, s


def verify_signature(message, h, s, base, order, public):
    V = (s * base) + (h * public)
    h_prime = hash(V, message, order)

    return h == h_prime


def identity_key_gen(base, order, message):
    secret, public = generate_key(base, order)
    h, s = sign(message, base, order, secret)
    IKRegReq(h, s, public.x, public.y)
    return secret


def get_server_public(base, order, server_public, pre_public):
    pre_public_x_encoded = EncodeInteger(pre_public.x)
    pre_public_y_encoded = EncodeInteger(pre_public.y)
    h, s = sign(pre_public_x_encoded + pre_public_y_encoded, base, order, secret)

    server_x, server_y, server_h, server_s = SPKReg(h, s, pre_public.x, pre_public.y)
    server_x_encoded = EncodeInteger(server_x)
    server_y_encoded = EncodeInteger(server_y)
    server_message_encoded = server_x_encoded + server_y_encoded

    is_verified = verify_signature(server_message_encoded, server_h, server_s, base, order, server_public)
    if is_verified:
        return server_x, server_y
    else:
        return "Could NOT verified!"


def signed_pre_key_gen(base, order, server_public):
    pre_secret, pre_public = generate_key(base, order)
    server_x, server_y = get_server_public(base, order, server_public, pre_public)
    return pre_secret, server_x, server_y


def reset_spk(message, base, order, secret):
    h, s = sign(message,base, order, secret)
    ResetSPK(h, s)


def HMAC_key_generator(pre_secret, server_public, order):
        t = pre_secret * server_public

        t_x_encoded = EncodeInteger(t.x)
        t_y_encoded = EncodeInteger(t.y)
        constant = b"NoNeedToRideAndHide"

        token = t_x_encoded + t_y_encoded + constant

        hmac_key = SHA3_256.new(token).digest()
        hmac_key = int.from_bytes(hmac_key, byteorder='big') % order
        return hmac_key


def OTK_generator(hmac_key, base, order):
    otk_secret, otk_public = generate_key(base, order)
    pub_x_encoded = EncodeInteger(otk_public.x)
    pub_y_encoded = EncodeInteger(otk_public.y)

    token = pub_x_encoded + pub_y_encoded

    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(token)
    hmac = h.hexdigest()

    return otk_secret, otk_public, hmac

def reset_OTK(message, base, order, secret):
    h, s = sign(message, base, order, secret)
    ResetOTK(h, s)


# <------------------------------------------- PHASE 2 ------------------------------------------->

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)
    print(response.json())

#get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())


secret = 105668584835639248110395564052634711393246753382510027123035358816083062246229
pre_secret = 11022507722748211318083952379512342912848718017689188451915389070077053236957
server_x, server_y = get_server_public(P, n, IKey_Ser, get_public(pre_secret, P))
server_public = Point(server_x, server_y, curve)
otks = [
    102127995807509019984616021483748299503088552662483211078908110166993238941727,
    8847861909179070053759416306749886903220739982888450423578017887789147916462,
    80528234922354478984826033446629779397576699891352901506023282544459751005703,
    40025279242573119052046381269521109583987283504804243196102491475672313469198,
    70119872140551191171656819964296773852571958155565760901182074313366495862048,
    105943573475387730258642538886968851770938915979706257010505004314826504217564,
    54706271495314621022563115572601280119558617171799792646375583594129403955140,
    60932826942249601604670754640489243398729641268719780986896217424555600590262,
    48324104802456580670337241475707310984501663999799083727160420070075793302453,
    74305934171649853661245075569791426077815285739465306938888662290362949786118,
]


def CreateSessionKey(otk_pri, ek_pub):
    T = otk_pri * ek_pub
    t_x_encoded = EncodeInteger(T.x)
    t_y_encoded = EncodeInteger(T.y)
    constant = b"MadMadWorld"

    u = t_x_encoded + t_y_encoded + constant
    session_key = SHA3_256.new(u).digest()

    return session_key


def KeyDerivation(kdf_key):
    constant_enc = b"LeaveMeAlone"
    constant_hmac = b"GlovesAndSteeringWheel"
    constant_next = b"YouWillNotHaveTheDrink"

    k_enc = SHA3_256.new(kdf_key + constant_enc).digest()
    k_hmac = SHA3_256.new(k_enc + constant_hmac).digest()
    k_next = SHA3_256.new(k_hmac + constant_next).digest()

    return k_enc, k_hmac, k_next


def DecryptMsg(msg_token, k_enc, k_hmac):

    nonce = msg_token[0:8]
    msg = msg_token[8:-32]
    mac_value = msg_token[-32:]

    hmac = HMAC.new(k_hmac, digestmod=SHA256)
    hmac.update(msg)
    hmac_value = hmac.digest()

    is_verified = (mac_value == hmac_value)

    if is_verified:
        cipher = AES.new(k_enc, mode=AES.MODE_CTR, nonce=nonce)
        plaintext_encoded = cipher.decrypt(msg)
        plaintext = plaintext_encoded.decode('utf-8')
        return plaintext
    else:
        return 'INVALIDHMAC'


# <------------------------------------------- PHASE 3 ------------------------------------------->

def SendMsg(idA, idB, otkid, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkid), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())


def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB': stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json())
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
    else:
        return -1, 0, 0


def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


myID = 26853

def recieveRecieverOTK(id, reciever_id, base, order, secret):
    h, s = sign(EncodeInteger(reciever_id), base, order, secret)
    key_id, receiver_otk_x, receiver_otk_y = reqOTKB(id, reciever_id, h, s)
    return key_id, receiver_otk_x, receiver_otk_y

def encryptMessage(message, k_enc, k_hmac):
    nonce = get_random_bytes(8)

    encrypted_message = AES.new(k_enc, AES.MODE_CTR, nonce=nonce).encrypt(message)

    hmac = HMAC.new(k_hmac, digestmod=SHA256)
    hmac.update(message)
    hmac_value = hmac.digest()

    msg_encoded = nonce + encrypted_message + hmac_value
    msg = (int.from_bytes(msg_encoded, byteorder='big'))
    return msg

#
# Recieve 5 messages from server
#

message = 26853
message_encoded = EncodeInteger(message)
h, s = sign(message_encoded, P, n, secret)

PseudoSendMsg(h, s)

server_id = 18007

#
# Decrypt first message with session key
#
sender_id, sender_otk_id, sender_msg_id, msg, ek_pub_x, ek_pub_y = ReqMsg(h, s)

sender_ek_pub = Point(ek_pub_x, ek_pub_y, curve)
session_key_encoded_receive = CreateSessionKey(otks[sender_otk_id], sender_ek_pub)
k_enc_encoded_receive, k_hmac_encoded_receive, kdf_key_encoded_receive = KeyDerivation(session_key_encoded_receive)

msg_encoded = EncodeInteger(msg)
plaintext = DecryptMsg(msg_encoded, k_enc_encoded_receive, k_hmac_encoded_receive)
plaintext_encoded = plaintext.encode('utf-8')


#
# Receive OTK of the recipient
#

current_otk, receiver_otk_x, receiver_otk_y = recieveRecieverOTK(myID, server_id, P, n, secret)


#
# Encrypt first message and send it
#

if current_otk != -1:
    ek = get_public(otks[sender_otk_id], P)
    receiver_otk_public = Point(receiver_otk_x, receiver_otk_y, curve)

    session_key_encoded_send = CreateSessionKey(otks[sender_otk_id], receiver_otk_public)
    k_enc_encoded_send, k_hmac_encoded_send, kdf_key_encoded_send = KeyDerivation(session_key_encoded_send)
    SendMsg(myID, server_id, current_otk, 1, encryptMessage(plaintext_encoded, k_enc_encoded_send, k_hmac_encoded_send), ek.x, ek.y)

    #
    # Repeat for the next 4 messages
    #

    for x in range(1, 5):
        k_enc_encoded_receive, k_hmac_encoded_receive, kdf_key_encoded_receive = KeyDerivation(kdf_key_encoded_receive)
        sender_id, sender_otk_id, sender_msg_id, msg, ek_pub_x, ek_pub_y = ReqMsg(h, s)
        msg_encoded = EncodeInteger(msg)

        plaintext = DecryptMsg(msg_encoded, k_enc_encoded_receive, k_hmac_encoded_receive)
        plaintext_encoded = plaintext.encode('utf-8')

        k_enc_encoded_Send, k_hmac_encoded_send, kdf_key_encoded_send = KeyDerivation(kdf_key_encoded_send)
        SendMsg(myID, server_id, sender_otk_id, x + 1, encryptMessage(plaintext_encoded, k_enc_encoded_Send, k_hmac_encoded_send), ek.x, ek.y)

else:
    print("INVALID OTK FOR THE RECIPIENT")


#
# Check the status of your OTKs
#

h, s = sign(EncodeInteger(myID), P,  n, secret)
Status(myID, h, s)
