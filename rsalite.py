
import argparse
import binascii
import hashlib
import hmac
import logging
import os
from socket import socket, AF_INET, SOCK_STREAM

tls_ClientHello = bytearray((
    0x16, 0x03, 0x03,               #  +0 content type: handshake, TLS1.2
    0x00, 0x2f,                     #  +3 content length (len(ClientHello)-5)
    0x01,                           #  +5 handhsake type: ClientHello
    0x00, 0x00, 0x2b,               #  +6 length (len(ClientHello)-9)
    0x03, 0x03,                     #  +9 TLS1.2
    0x00, 0x00, 0x00, 0x00,         # +11 random: timestamp
    0x00, 0x00, 0x00, 0x00, 0x00,   # +15 random: value (28 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
    0x00,                           # +43 session id
    0x00, 0x02,                     # +44 cypher suites len (in bytes)
    0x00, 0x3c,                     # +46 TLS_RSA_WITH_AES_128_CBC_SHA256
    0x01, 0x00,                     # +48 one compression method: null
    0x00, 0x00,                     # +50 extensions length: 0
))

tls_ClientKeyExchange = bytearray((
    0x16, 0x03, 0x03,               #  +0 content type: handshake, TLS1.2
    0x00, 0x00,                     #  +3 content length (len(ClientKeyExchange)-5)
    0x10,                           #  +5 handhsake type: ClientKeyExchange
    0x00, 0x00, 0x00,               #  +6 length (len(ClientKeyExchange)-9)
    0x00, 0x00,                     #  +9 enc_pre_master length
    # and then the value (modulus_len bytes)
))

tls_ChangeCipherSpec = bytearray((
    0x14, 0x03, 0x03,               #  +0 content type: Change Cipher Spec, TLS1.2
    0x00, 0x01, 0x01,               #  +3 length(1), msg type: Change Cipher Spec (1) 
))

tls_EncryptedHandshakeMessage = bytearray((
    0x16, 0x03, 0x03,               #  +0 content type: handshake, TLS1.2
    0x00, 0x00,                     #  +3 content length
    # and then the value (12 bytes)
))

sock = None                         # socket.socket

buff = bytearray(100)               # input parsing buffer
idx = 0                             # index in input element

handshake_hash = hashlib.sha256()   # content of TLS handshake, excluding record headers

client_random = bytearray(32)       # TLS time_stamp(4B)+client_random(28B)
server_random = bytearray(32)       # TLS time_stamp(4B)+server_random(28B)

master_secret = bytearray(48)       # TLS master_secret

modulus = bytearray(256)            # should be 256B for 2048bit key length
modulus_len = 0
exponent = bytearray(10)            # XXX: find out max exponent size
exponent_len = 0

def read_octets(count, ignore=False, update_hash=True):
    """read count octets from input into 'buff' and update 'idx'"""
    global sock, buff, idx

    if ignore:
        # don't store the data, but still update the handshake hash
        handshake_hash.update(sock.recv(count))
        logging.debug('<<< ignored {} octets'.format(count))
    else:
        sock.recv_into(buff, count)
        if update_hash:
            handshake_hash.update(buff[:count])
        logging.debug('<<< {}'.format(binascii.hexlify(buff[:count])))
    idx += count

def send_client_hello():
    """generate client random and send initial ClientHello msg"""
    global sock, client_random

    client_random = bytearray(os.urandom(32))           # timestamp(4)+random(28)
    tls_ClientHello[11:11+32] = client_random
    logging.info('Sending ClientHello')
    logging.info('  timestamp+client_random = {}'.format(binascii.hexlify(client_random)))
    n = sock.send(tls_ClientHello)
    handshake_hash.update(tls_ClientHello[5:])
    logging.debug('>>> {}'.format(binascii.hexlify(tls_ClientHello)))
    assert n == len(tls_ClientHello)

def parse_server_hello():
    global idx, server_random

    logging.info('Receiving ServerHello')
    read_octets(5, update_hash=False)
    assert buff[0:3] == bytearray((0x16, 0x03, 0x03))   # handshake, TLS1.2
    length = int.from_bytes(buff[3:5], byteorder='big') # ServerHello length
    idx = 0                                             # start counting ServerHello length
    read_octets(39)
    assert buff[0] == 0x02                              # ServerHello
    assert buff[4:6] == bytearray((0x03, 0x03))         # TLS1.2
    server_random = buff[6:6+32]                        # server timestamp+random
    logging.info('  timestamp+server_random = {}'.format(binascii.hexlify(server_random)))
    sess_len = int(buff[38])
    read_octets(sess_len, ignore=True)                  # ignore sessionID
    read_octets(3)
    assert buff[0:3] == bytearray((0x00, 0x3c, 0x00))   # TLS_RSA_WITH_AES_128_CBC_SHA256
    assert length == idx                                # no garbage at the end

# ASN1 mini into
# (tag, length, value)
# tag (1byte) -        https://msdn.microsoft.com/en-us/library/windows/desktop/bb648642(v=vs.85).aspx
# length (N bytes)     https://msdn.microsoft.com/en-us/library/windows/desktop/bb648641(v=vs.85).aspx
#   N==1 byte  - for   0<= len(value) < 128     (len value 1byte)
#   N==2 bytes - for 128<= len(value) < 256     (0x81, len value 1byte)
#   N==3 bytes - for 256<= len(value) < 65556   (0x82, len value 2bytes)
# value (1..length bytes) - defined by tag

ASN1_INTEGER    = 0x02
ASN1_BITSTRING  = 0x03
ASN1_SEQUENCE   = 0x30

def asn1_tag_and_len(expect_tag=None):
    """read tag (1B) and length (variable) and return"""
    read_octets(2)
    tag = buff[0]                                       # first byte is tag
    if expect_tag is not None:
        assert tag == expect_tag
    length = int(buff[1])                               # second byte is length, if value < 128
    if length & 0x80:
        lenlen = length & 0x7f                          # otherwise, second byte is the length of length
        assert 1 <= lenlen <=4
        read_octets(lenlen)
        length = int.from_bytes(buff[:lenlen], byteorder='big')
    logging.debug('ASN1 tag={}, len={}'.format(hex(tag), length))
    return length

def asn1_skip_node():
    """read ASN1 header and position yourself after the value"""
    length = asn1_tag_and_len()
    read_octets(length, ignore=True)

def asn1_read_integer(into, max_size):
    """read INTEGER into 'into' bytearray, expecting unsigned int value"""
    global sock, idx

    length = asn1_tag_and_len(expect_tag=ASN1_INTEGER)
    read_octets(1)                                      # ASN.1 INTEGER is encoded as two's complement
    leading_zero = (buff[0] == 0x00)                    #   large uint will start with leading 0x00, strip it
    if not leading_zero:
        into[0] = buff[0]
        into = memoryview(into)[1:]                     # .. similar to into+1 in C
    assert length-1 <= max_size
    sock.recv_into(into, length-1)                      # (ugly) this is the ONLY place I read sock outside read_octets
    handshake_hash.update(into[:length-1])              # must update handshake_hash as well (!)
    logging.debug('<<< {}'.format(binascii.hexlify(into[:length-1])))
    idx += length-1
    if leading_zero:                                    # return size of data, not input bytes read
        return length-1
    return length

def parse_server_certificate():
    global modulus_len, exponent_len, sock, idx

    logging.info('Receiving ServerCertificate')
    read_octets(5, update_hash=False)
    assert buff[0:3] == bytearray((0x16, 0x03, 0x03))   # handshake, TLS1.2
    length = int.from_bytes(buff[3:5], byteorder='big') # Certificate length
    logging.debug('  certificate len = {}'.format(length))
    idx = 0
    read_octets(10)
    assert buff[0] == 0x0b                              # Certificate type
    cert_len = int.from_bytes(buff[1:4], byteorder='big') # Certificate length

    # DER parsing starts here (https://tools.ietf.org/html/rfc2459#section-4.1)
    asn1_tag_and_len(expect_tag=ASN1_SEQUENCE)          # Certificate SEQUENCE
    asn1_tag_and_len(expect_tag=ASN1_SEQUENCE)          # TBSCertificate SEQUENCE

    logging.info('  reading certificate version')
    read_octets(5)                                      # [0] EXPLICIT Version INTEGER
    assert buff[0:5] == bytearray((0xa0, 0x03, 0x02, 0x01, 0x02))
    # a0 (explicit) 03 (len?) 02 (integer tag) 01 (len) 02 (value == v3)

    asn1_skip_node()                                    # serialNumber
    asn1_skip_node()                                    # signature
    asn1_skip_node()                                    # issuer
    asn1_skip_node()                                    # validity
    asn1_skip_node()                                    # subject

    asn1_tag_and_len(expect_tag=ASN1_SEQUENCE)          # SubjectPublicKeyInfo SEQUENCE
    logging.info('  reading public key algorith')
    read_octets(15)                                     # algorithm AlgorithmIdentifier
    # SEQUENCE { algorithm (OID, tag 0x06), parameters (0) }
    # Algorithm Id: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    assert buff[0:15] == bytearray((0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00))

    # inside the bitsting is ASN.1 encoded RSA public key (yes, ASN.1 inside ANS.1)
    asn1_tag_and_len(expect_tag=ASN1_BITSTRING)         # subjectPublicKey BIT STRING
    read_octets(1)                                      # padding of bitstring (to multiply of 8)
    assert buff[0] == 0x0

    # RSA public key (https://tools.ietf.org/html/rfc2459#section-7.3.1)
    asn1_tag_and_len(expect_tag=ASN1_SEQUENCE)          # RSAPublicKey SEQUENCE

    modulus_len = asn1_read_integer(modulus, 256)
    logging.info('  modulus = {}.. (len={})'.format(binascii.hexlify(modulus[:40]), modulus_len))
    exponent_len = asn1_read_integer(exponent, 10)
    logging.info('  exponent = {} (len={})'.format(binascii.hexlify(exponent[:exponent_len]), exponent_len))

    read_octets(length-idx, ignore=True)                # skip to the end of this ANS.1 nightmare

def parse_server_hello_done():
    global idx, server_random

    logging.info('Receiving ServerHelloDone')
    read_octets(5, update_hash=False)
    assert buff[0:5] == bytearray((0x16, 0x03, 0x03, 0x00, 0x04))   # handshake, TLS1.2, len=4
    read_octets(4)
    assert buff[0:4] == bytearray((0x0e, 0x00, 0x00, 0x00))         #   ServerHelloDone, len=0

def rsa_encrypt(pre_master):
    n = int.from_bytes(modulus[:modulus_len], byteorder='big')
    e = int.from_bytes(exponent[:exponent_len], byteorder='big')

    # padding https://tools.ietf.org/html/rfc2313#section-8.1
    padlength = modulus_len - 48 - 3                    # RSA pre-master is 48 bytes
    padded_msg = bytearray(modulus_len)
    padded_msg[0] = 0x00
    padded_msg[1] = 0x02
    padded_msg[2:padlength+2] = (0xff, )*padlength      # padding SHOULD be random as well
    padded_msg[padlength+2] = 0x00
    padded_msg[padlength+3:] = pre_master
    logging.debug('padded RSA message {}'.format(binascii.hexlify(padded_msg)))
    assert len(padded_msg) == modulus_len

    m = int.from_bytes(padded_msg, byteorder='big')
    c = pow(m, e, n)                                    # RSA encryption ( <msg>^<exp> % <modulus> )

    return c.to_bytes(modulus_len, byteorder='big')

def HMAC_SHA256(k, b):
    return bytearray(hmac.new(bytes(k), bytes(b), hashlib.sha256).digest())


def P_hash(macFunc, secret, seed, length):
    bytes = bytearray(length)
    A = seed
    index = 0
    while 1:
        A = macFunc(secret, A)
        output = macFunc(secret, A + seed)
        for c in output:
            if index >= length:
                return bytes
            bytes[index] = c
            index += 1
    return bytes


def PRF_1_2(secret, label, seed, length):
    """copied from tlslite"""
    # https://tools.ietf.org/html/rfc5246#section-5
    return P_hash(HMAC_SHA256, secret, label + seed, length)


def send_client_key_exchange():
    """generate pre_master and send out encrypted by server's RSA pub key"""
    global master_secret, client_random, server_random

    logging.info('Sending ClientKeyExchange')
    pre_master = bytearray((0x03, 0x03)) + bytearray(os.urandom(46))
    master_secret = PRF_1_2(pre_master, b'master secret', client_random+server_random, 48)
    logging.debug('  pre_master = {} (not sent)'.format(binascii.hexlify(pre_master)))
    logging.debug('  master_secret = {} (not sent)'.format(binascii.hexlify(master_secret)))
    enc_pre_master = rsa_encrypt(pre_master)
    assert len(enc_pre_master) == modulus_len

    tls_ClientKeyExchange[9:11] = modulus_len.to_bytes(2, byteorder='big')
    tls_ClientKeyExchange[6:9]  = (modulus_len+2).to_bytes(3, byteorder='big')
    tls_ClientKeyExchange[3:5]  = (modulus_len+6).to_bytes(2, byteorder='big')
    n = sock.send(tls_ClientKeyExchange)
    handshake_hash.update(tls_ClientKeyExchange[5:])
    logging.debug('>>> {}'.format(binascii.hexlify(tls_ClientKeyExchange)))
    assert n == len(tls_ClientKeyExchange)
    n = sock.send(enc_pre_master)
    handshake_hash.update(enc_pre_master)
    logging.debug('>>> {}'.format(binascii.hexlify(enc_pre_master)))
    assert n == len(enc_pre_master)

def send_change_cipher_spec():
    """send ChangeCipherSpec to server"""

    logging.info('Sending ChangeCipherSpec')
    n = sock.send(tls_ChangeCipherSpec)
    #handshake_hash.update(tls_ChangeCipherSpec[5:])        # ChangeCipherSpec is not part of HandShake, don't hash it
    logging.debug('>>> {}'.format(binascii.hexlify(tls_ChangeCipherSpec)))
    assert n == len(tls_ChangeCipherSpec)


def send_encrypted_handshake_message():
    """XXX"""

    logging.info('Sending EncryptedHandshakeMessage')
    digest = handshake_hash.digest()                    # client is sending handshake hash up to THIS point
    logging.debug('  digest = {}'.format(binascii.hexlify(digest)))
    logging.debug('  master_secret = {}'.format(binascii.hexlify(master_secret)))
    verify_data = PRF_1_2(master_secret, b'client finished', digest, 12)
    logging.debug('  verify_data = {}'.format(binascii.hexlify(verify_data)))
    tls_EncryptedHandshakeMessage[3:5] = len(verify_data).to_bytes(2, byteorder='big')

    # XXX: needs to be encrypted, currently it is sent as plaintext
    n = sock.send(tls_EncryptedHandshakeMessage)
    logging.debug('>>> {}'.format(binascii.hexlify(tls_EncryptedHandshakeMessage)))
    assert n == len(tls_EncryptedHandshakeMessage)

    n = sock.send(verify_data)
    handshake_hash.update(verify_data)
    logging.debug('>>> {}'.format(binascii.hexlify(verify_data)))
    assert n == len(verify_data)

def connect(host, port):
    global sock, client_random

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((host, port))
    send_client_hello()
    parse_server_hello()
    parse_server_certificate()
    parse_server_hello_done()
    send_client_key_exchange()
    send_change_cipher_spec()
    send_encrypted_handshake_message()

    print('foooooo')
    read_octets(10)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbosity', action='count', default=0)
    parser.add_argument('host')
    parser.add_argument('port', type=int)
    args = parser.parse_args()

    logging.basicConfig(format='%(levelname)s %(message)s', level=logging.WARNING,)
    if args.verbosity > 1:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbosity > 0:
        logging.getLogger().setLevel(logging.INFO)

    connect(args.host, args.port)

if __name__ == '__main__':
    main()
