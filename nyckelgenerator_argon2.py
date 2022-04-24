#! /usr/bin/env python
# coding=utf-8
"""Genererar två st kryptonycklar

Denna modul bör köras som cli kommando och skapar då två symmetriska nycklar
baserad på inmatade data.

:Date: 2018-11-06
:Version: 1
:Author: Peter Franzén
"""
# Att göra:
#-Välja algoritm(er)
#-Konstanter

import argon2pure
import b64


def phc_hash(  #pylint: disable=R0913
        psk,
        salt,
        info=b"0",
        secret=b"",
        time_cost=12,
        memory_cost=1664,
        parallelism=8,
        tag_length=32,
        type_code=2):
    r"""gen_symnyckel skapar symmetrisk nyckel baserade på indata.

    :param bytearray psk: Pre-shared key - Delad hemlighet - lösenordet.
    :param bytearray salt: Slumptecken som används för att utöka styrkan på
        lösenordet. Should be random and different for each password.
    :param bytearray info: Sessionsinformation - data som gör nyckeln unik trots
        att samma lösen används flera gånger.
    :param bytearray secret: En valfri applikationsspecifik hemlighet som gör att genererade hashar
    blir applikationsspecifika.
    :param int time_cost: Tidkostnad för hashskapandet. Number of iterations to use.
    :param int memory_cost: Amount of kibibytes of memory to use.
    :param int parallelism: Amount of threads that can contribute to
        the computation of the hash at the same time.

    Optional arguments:
    :param int tag_length: Length of the hash returned
    :param int type_code: variant of argon2 to use.  Either ARGON2ID, ARGON2I or ARGON2D

    :raises TypeError om psk, salt eller info inte är av typen bytearray.
    :return: En 256 bitar lång bitsträng som kan användas som symmetrisk nyckel.
    :rtype: bytearray

    >>> import nyckelgenerator_argon2
    >>> nyckelgenerator_argon2.phc_hash(psk=b"12345678901234567890", salt=b"qwertyuiopqwertyuiop", time_cost=2, memory_cost=8, parallelism=1)
    b'\xc2\x06$\x90\xd3\x81A\xf7\xb8\xaa@\x10rd\x88S\xd9\xa9\xef\x1e\x8e8\xcc&&\xf7N3\xf6s\xa4o'
    """

    #import time

    #start = time.process_time()
    expand = argon2pure.argon2(password=psk,
                               salt=salt,
                               associated_data=info,
                               secret=secret,
                               time_cost=time_cost,
                               memory_cost=memory_cost,
                               parallelism=parallelism,
                               tag_length=tag_length,
                               type_code=type_code)

    #end = time.process_time()
    #print("Körtid: " + str(end - start))
    del psk
    del salt
    del info
    del secret
    return expand


if __name__ == '__main__':
    import os
    import base64
    import secrets
    import sys

    print(
        "nyckelgenerator_argon2 - ett script som genererar symmetriska kryptonycklar."
    )
    print("Scriptet är avsett för symmetriska nyckelförhandlingar.")
    print(
        "Logiken är baserad på argon2 - vinnaren av Password Hashing Contest.")
    print("https://password-hashing.net/")
    print("")
    print("För att få ett bra salt, kör följande kommando:")
    print("openssl rand 20 | openssl rmd160 -binary | base64")
    print("")
    print("Alla värden måste anges i base64-format")
    #print("'Salt' används för att 'smaksätta' lösenfrasen. Saltet ger
    #       lösenfrasen egenskaper som den inte har från början, och höjer
    #       tröskeln rejält för en motståndare.")
    #print("")
    print("Rekommenderad salt-längd är 16 tecken eller längre.")

    print("")
    SALT_SUGGEST = secrets.token_urlsafe(23)
    #INSALT = b64.base64url_decode(
    INSALT = bytes(input(f"Ange salt [{SALT_SUGGEST}]:"), "utf-8")

    if not 8 <= len(INSALT) <= 128:
        print(f"base64url_decode({SALT_SUGGEST}) används som salt")
        INSALT = b64.base64url_decode(bytes(SALT_SUGGEST, "utf-8"))

    print("")
    print(
        "Rekommenderad längd på hemligheten är minst 16 tecken, gärna längre.")
    print("")
    #INPSK = b64.base64url_decode(
    INPSK = bytes(input("Ange delad hemlighet (PSK): "), "utf-8")
    if not 8 <= len(INPSK) <= 512:
        print("Delad hemlighet ska vara mellan 8 -- 512 tecken.")
        print(f"Din hemlighet är {len(INPSK)} tecken lång. Försök igen")
        INSALT = None
        INPSK = None
        del INPSK
        sys.exit()

    #os.system('cls||clear')

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
    #if len(ININFO) == 0:
    if not ININFO:
        ININFO = b'0'
        print(f"tom sträng. Istället används: {ININFO}")
    else:
        if len(ININFO) > 1024:
            print("Sessionsinformation får vara max 1024 tecken.")
            #print("Din sessionsinformation är " + str(len(ININFO)) + " tecken lång. Försök igen")
            print(
                f"Din sessionsinformation är {len(ININFO)} tecken lång. Försök igen"
            )
            INSALT = None
            #INPSK = None
            del INPSK
            sys.exit()
    print("")
    print("128 bit = 16 byte, 256 bit = 32 byte")

    HASH_LEN = int(input("Hur många bytes nyckeldata behöver du?: "))
    if not 4 <= HASH_LEN <= 256:
        HASH_LEN = 32

    print("Skapar kryptonycklar...")
    KM = phc_hash(INPSK, INSALT, ININFO, tag_length=HASH_LEN * 2)
    INPSK = None
    INSALT = None
    ININFO = None

    HALFSIZE = int(len(KM) / 2)

    KM1 = KM[0:HALFSIZE]
    KM2 = KM[HALFSIZE:len(KM)]

    KM = None

    print(
        "--------------------------------------------------------------------------------"
    )
    print("")
    print("Krypteringsnyckel:")
    print(f"           Base64: {b64.base64url_encode(KM1).decode('utf8')}")
    print(f"           Base32: {b64.base32_encode(KM1).decode('utf8')}")
    print(f"              Hex: {base64.b16encode(KM1).decode('utf8')}")

    print("")
    print("Signeringsnyckel:")
    print(f"          Base64: {b64.base64url_encode(KM2).decode('utf8')}")
    print(f"          Base32: {b64.base32_encode(KM2).decode('utf8')}")
    print(f"             Hex: {base64.b16encode(KM2).decode('utf8')}")

    print("")
    KLAR = input(
        "När du har kopierat nycklarna, tryck på Enter för att rensa skärmen.")

    os.system('cls||clear')
