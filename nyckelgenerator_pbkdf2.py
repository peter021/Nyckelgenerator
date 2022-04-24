#!/usr/bin/env python3
# coding=utf-8

# pylint: disable=C0301, W0105
"""Genererar två st 256 bit kryptonycklar

Denna modul bör köras som cli kommando och skapar då två symmetriska nycklar
baserad på inmatade data.

:Date: 2018-11-06
:Version: 1
:Author: Peter Franzén
"""

# Att göra:
#-Välja algoritm(er)
#-Konstanter

import hmac
import hashlib
import sys
import time


def gen_sym_nyckel(psk, salt, info, algo="sha512", iterationer=1048576):
    """gen_symnyckel skapar symmetrisk nyckel baserade på indata.

    :param bytearray psk: Pre-shared key - Delad hemlighet - lösenordet.
    :param bytearray salt: Slumptecken som används för att utöka styrkan på lösenordet.
    :param bytearray info: Sessionsinformation - data som gör nyckeln unik trots att samma lösen
    används flera gånger.
    :param str algo: Vilken hashalgoritm ska användas för nyckelskapandet. Endast "sha512" fungerar.
    :raises TypeError om psk, salt eller info inte är av typen bytearray.
    :return: En 512 bitar lång bitsträng som kan användas som symmetrisk nyckel.
    :rtype: bytearray

    >from gen_sym_nyckel import gen_sym_nyckel
    >gen_sym_nyckel(b"abcdefgh", b"12345678", b"qwertyuiop")
    b'\x84~Ml\xf0\xb3\xe7\xd3\xc7>0j\xf8U5\x96\xa2}?h\x07L\x10\xe7.\xdf\xba\xba\xc4\xca\xbc?\xd7\xbeL\x12\xa5\x83\xad\xf0\x95\x85\xa2\xcd\x16\xca\x99\xbaI\xa8\x13T\xe1\x9f\x9b\xcfs\xe0,\xa6H;\x1a\x13'
    """
    # 1048576 iterationer tar 1.479692143 sekunder = datorn klarar
    #ca 708 645 st HMAC-SHA512 beräkningar per sekund...

    # extract randomized
    kdk = hmac.new(key=salt, msg=psk, digestmod=algo).digest()
    salt = None
    del salt
    psk = None
    del psk

    #expand key
    #start = time.process_time()
    expand = hashlib.pbkdf2_hmac(algo, info, kdk, iterationer)
    #end = time.process_time()
    #print("Körtid: " + str(end - start))
    kdk = None
    del kdk
    info = None
    del info
    return expand


if __name__ == '__main__':
    """
    Genererar symmetriska nycklar

    .. data:: DEFITERATIONER
        Förvalt antal iterationer

    .. data:: ALGONAME
            Förvald algoritm för pbkdf2_hmac(<algoritm>)-funktionen
    """
    #print(hashlib.algorithms_guaranteed)
    #print(hashlib.algorithms_available)

    # DEFITERATIONER = 3599968  #SHA512
    DEFITERATIONER = 1703098  #Whirlpool
    #ALGONAME = "sha512"
    ALGONAME = "whirlpool"

    import os
    import b64
    import secrets
    print(
        "gen_sym_nyckel - ett script som genererar symmetriska kryptonycklar.")
    print("Scriptet är avsett för symmetriska nyckelförhandlingar.")
    print("Logiken är inspirerat av extract-expand metoden i NIST SP 800-56C,")
    print(
        "men istället för den Hash-based Key Derivation Function (HKDF) som definieras i"
    )
    print(
        f"NIST SP 800-108 används PBKDF2-HMAC({ALGONAME}) med {DEFITERATIONER} iterationer."
    )
    print("")
    print("'Salt' används för att 'smaksätta' lösenfrasen. Saltet ger " +
          "lösenfrasen egenskaper som den inte har från början, och höjer " +
          "tröskeln rejält för en motståndare.")
    print("")
    print("Rekommenderad salt-längd är 16 tecken eller längre.")
    print("")

    SALT_SUGGEST = secrets.token_urlsafe(20)
    INSALT = b64.base64url_decode(
        bytes(input(f"Ange salt [{SALT_SUGGEST}]:"), "utf-8"))

    if not 8 <= len(INSALT) <= 128:
        print(f"{SALT_SUGGEST} används som salt")
        INSALT = b64.base64url_decode(bytes(SALT_SUGGEST, "utf-8"))

    print("")
    print(
        "Rekommenderad längd på hemligheten är minst 16 tecken, gärna längre.")
    print("")
    INPSK = bytes(input("Ange delad hemlighet (PSK): "), "utf-8")
    if not 8 <= len(INPSK) <= 512:
        print("Delad hemlighet ska vara mellan 8 -- 512 tecken.")
        print(f"Din hemlighet är {len(INPSK)} tecken lång. Försök igen")
        INSALT = None
        INPSK = None
        del INPSK
        sys.exit()

    os.system('cls||clear')

    print(
        "Sessionsinformation är applikations- och kontextbaserad information" +
        "som minskar risken för att samma nyckel används flera gånger.")
    print("")
    print("Sessionsinformation kan förslagsvis bestå av:")
    print("-Någon datumkomponent, t ex år, månad, vecka, datum, UTC-timestamp")
    print(
        "-Sändare & Mottagare - så att olika nycklar används i olika riktningar"
    )
    print("-Engångsvärde, t ex ett såkallat nonce.")
    print("     Detta kan skickas okrypterat med försändelsen.")
    print("-Etikett - en förväntad textsträng")
    print(
        "-Protokoll, algoritm, räknare, ärende, identiteter eller annan sessionsinfo"
    )
    print("")
    print("Max 1024 tecken.")
    print("")
    ININFO = bytes(input("Ange sessionsinformation: "), "utf-8")

    if not ININFO:
        ININFO = b'0'
        print(f"tom sträng. Istället används: {ININFO}")
    else:
        if len(ININFO) > 1024:
            print("Sessionsinformation får vara max 1024 tecken.")
            print(
                f"Din sessionsinformation är {len(ININFO)} tecken lång. Försök igen"
            )
            INSALT = None
            #INPSK = None
            del INPSK
            sys.exit()
    print("")
    print("Skapar kryptonycklar...")
    KM = gen_sym_nyckel(INPSK,
                        INSALT,
                        ININFO,
                        ALGONAME,
                        iterationer=DEFITERATIONER)
    INPSK = None
    INSALT = None
    ININFO = None

    HALFSIZE = int(len(KM) / 2)

    KM1 = KM[0:HALFSIZE]
    KM2 = KM[HALFSIZE:len(KM)]

    KM = None

    KM1B = b64.base64url_encode(KM1)
    KM2B = b64.base64url_encode(KM2)
    print(
        "--------------------------------------------------------------------------------"
    )
    print("")
    print("Krypteringsnyckel: " + KM1B.decode("utf8"))
    print("")
    print("Signeringsnyckel: " + KM2B.decode("utf8"))
    print("")
    KLAR = input(
        "När du har kopierat nycklarna, tryck på Enter för att rensa skärmen.")

    os.system('cls||clear')
