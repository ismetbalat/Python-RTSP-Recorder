# ************************ HTTP Authentication İşlemi ***************************************************************
#
# Detay için Tıklayınız: https://kerteriz.net/http-authentication-yontemleri-ve-kullanimlari/
#
#
# *******************************************************************************************************************

import base64,hashlib


# Basic Authentication
def basicAuth(kullanici,sifre):
    authSeq = base64.b64encode((kullanici + ":" + sifre).encode("ascii"))
    authSeq = "Basic " + authSeq.decode('ascii')
    
    return authSeq




# Digest Authentication
def digestAuth(realm,nonce,kullanici,sifre,method,uri):
        
    m1 = hashlib.md5((kullanici + ":" + realm + ":" + sifre).encode("utf-8")).hexdigest()
    m2 = hashlib.md5((method + ":" + uri).encode("utf-8")).hexdigest()
    response = hashlib.md5((m1 + ":" + nonce + ":" + m2).encode("utf-8")).hexdigest()

    authSeq = "Digest "
    authSeq += "username=\"" + kullanici + "\", "
    authSeq += "realm=\"" + realm + "\", "
    authSeq += "algorithm=\"MD5\", "
    authSeq += "nonce=\"" + nonce + "\", "    
    authSeq += "uri=\"" + uri + "\", "
    authSeq += "response=\"" + response + "\""

    return authSeq