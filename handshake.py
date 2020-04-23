## RTSP Handshake ##


def msg_HI(url):
    msgRet = "DESCRIBE " + url + " RTSP/1.0\r\n"
    msgRet += "\r\n"
    return msgRet


def msg_OPTIONS(url,seq,userAgent,sessionId,authSeq):
    msgRet = "OPTIONS " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += "Authorization: " + authSeq + "\r\n"
    msgRet += "User-Agent: " + userAgent + "\r\n"
    msgRet += "Session: " + sessionId + "\r\n"
    msgRet += "\r\n"
    return msgRet


def msg_DESCRIBE(url,seq,userAgent,authSeq):
    msgRet = "DESCRIBE " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += "Authorization: " + authSeq + "\r\n"
    msgRet += "User-Agent: " + userAgent + "\r\n"
    msgRet += "Accept: application/sdp\r\n"
    msgRet += "\r\n"
    return msgRet

    
def msg_SETUP(url,seq,userAgent,authSeq,clientports):
    msgRet = "SETUP " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += "Authorization: " + authSeq + "\r\n"
    msgRet += "User-Agent: " + userAgent + "\r\n"
    msgRet += "Blocksize: 65535\r\n"
    msgRet += "Transport: RTP/AVP;unicast;client_port="+str(clientports[0])+"-"+str(clientports[1])+"\r\n"
    msgRet += "\r\n"
    return msgRet


def msg_PLAY(url,seq,userAgent,sessionId,authSeq):
    msgRet = "PLAY " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += "Authorization: " + authSeq + "\r\n"
    msgRet += "User-Agent: " + userAgent + "\r\n"
    msgRet += "Session: " + sessionId + "\r\n"
    msgRet += "Range: npt=0.000-\r\n"
    msgRet += "\r\n"
    return msgRet


def msg_TEARDOWN(url,seq,userAgent,sessionId,authSeq):
    msgRet = "TEARDOWN " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += "Authorization: " + authSeq + "\r\n"
    msgRet += "User-Agent: " + userAgent + "\r\n"
    msgRet += "Session: " + sessionId + "\r\n"
    msgRet += "\r\n"
    return msgRet



# Realm ve Nonce çek
def realm_nonce_cek(cevap):
    # Realm değeri
    start = cevap.find("realm")
    begin = cevap.find("\"", start)
    end = cevap.find("\"", begin + 1)
    realm = cevap[begin+1:end]

    # Nonce değeri
    start = cevap.find("nonce")
    begin = cevap.find("\"", start)
    end = cevap.find("\"", begin + 1)
    nonce = cevap[begin+1:end]

    return [realm,nonce]



def kanalCek(strContent):
    mapRetInf = []
    messageStrings = strContent.split("\n")
    for element in messageStrings:        
        if(element[:10] == "a=control:" and element[10:11] != "*"):
            kanal = element[10:].split("\r")
            mapRetInf.append(kanal[0])
    return mapRetInf


def videoParams(cevap):
    start = cevap.find("a=rtpmap:")
    end = cevap.find("\n", start + 9)
    rtpmap = cevap[start+9:end]

    start = cevap.find("a=videoinfo:")
    end = cevap.find("\n", start + 12)
    videoinfo = cevap[start+12:end]     

    start = cevap.find("a=fmtp:")
    end = cevap.find(";", start + 7)
    fmtp = cevap[start+7:end]

    start = cevap.find("sprop-parameter-sets=")
    end = cevap.find("\n", start + 21)
    sprop = cevap[start+21:end]
    

    return [rtpmap,videoinfo,fmtp,sprop]


def sesID(cevap):
    messageStrings = cevap.split("\n")
    for element in messageStrings:
        if "Session" in element:
            a = element.find(":")
            b = element.find(";")
            mapRetInf = element[a+2:b]
    return mapRetInf 