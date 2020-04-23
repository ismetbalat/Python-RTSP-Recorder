import socket, sys, bitstring, string, base64
import auth
import handshake
import packetHandler


# ************************ Bağlantı Bilgileri ve Ön Ayarlar *********************************************************
ip = "203.67.18.25"                                         # Kamera IP adresi
uri = "/0"                                                  # İstekte bulunduğumuz uri
rtspAdres = "rtsp://" + ip + uri                            # Kamera RTSP yayın adresi
kullanici = "admin"                                         # Kullanıcı adı
sifre = "admin"                                             # Şifre
serverport = 554                                            # RTSP Server portu (default. 554)
clientports = [60784,60785]                                 # Akışı çekeceğimiz rastgele iki port
fname = "stream.h264"                                       # Akışın kaydedileceği dosya
rn = 5000                                                   # Alınacak paket adedi
bufLen = 4096                                               # Socket buffer boyutu
userAgent = "Kerteriz RTSP"                                 # Agent ismi
seq = 1                                                     # Handshake esnasındaki komut sıra numarası. (Her işlemde artacak)
timeout = 3                                                 # Sunucudan cevap için beklenen süre. (Zaman Aşımı)
# *******************************************************************************************************************





# ************************ Socket Başlatıyoruz ***********************************************************************
#
# Detay için Tıklayınız: https://kerteriz.net/python-socket-programlama-nedir/
#

try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip,serverport)) 
except socket.timeout:
    print('!! Server yanıt vermedi !!')

#
# *******************************************************************************************************************







# ************************ Merhaba Mesajı ***************************************************************************
#
# Sunucuya merhaba diyerek hangi authentication yöntemini kullandığını öğreniyoruz.
#

mesaj = handshake.msg_HI(rtspAdres)
gonder = s.send(mesaj.encode('utf-8'))
cevap = s.recv(bufLen).decode('utf-8')

# Önizleme
print(mesaj)
print(cevap)

#
# Gelen mesah içindeki 'WWW-Authenticate:' başlığı kontrol edilerek yöntem belirlenir
#

isAuth = True
isBasic = False
isDigest = False
kontrol_auth = cevap.find('WWW-Authenticate:')
kontrol_basic = cevap.find('WWW-Authenticate: Basic')
kontrol_digest = cevap.find('WWW-Authenticate: Digest')

if kontrol_auth > 0:
    if kontrol_basic > 0:
        print('== HTTP Authentication: Basic ==\n')
        isBasic = True
    elif kontrol_digest > 0:
        print('== HTTP Authentication: Digest ==\n')    
        isDigest = True
    else:
        print('!! Farklı bir doğrulama yöntemi kullanılıyor !!')
        print('!! Şimdilik sadece Basic ve Digest destekliyoruz !!\n')
        yontem = cevap.find('WWW-Authenticate:')
        print(cevap[yontem:])
        sys.exit()
else:
    print('== HTTP Authentication kullanılmıyor ==\n')
    isAuth = False

#
# Gelen mesah içindeki 'realm' ve 'nonce' değerini çek
#

realm = handshake.realm_nonce_cek(cevap)[0]
nonce = handshake.realm_nonce_cek(cevap)[1]

print("*"*30)
print("Realm: " + realm + "\n" + "Nonce: " + nonce)
print("*"*30 + "\n")
#
# *******************************************************************************************************************







# ************************ El Sıkışmalar ****************************************************************************
#
# Artık sırasıyla ek sıkışmaları tamamlayarak akışı başlatıyoruz.
#
# ******************************************************************************************************************* DESCRIBE 

if(isAuth):
    if(isBasic):
        authSeq = auth.basicAuth(kullanici,sifre)
    elif(isDigest):
        authSeq = auth.digestAuth(realm,nonce,kullanici,sifre,"DESCRIBE",uri)
    else:
        print('!! Authentication ile ilgili bir problem var !!\n')
        sys.exit()
else:
    authSeq = ""

mesaj = handshake.msg_DESCRIBE(rtspAdres,seq,userAgent,authSeq)
gonder = s.send(mesaj.encode('utf-8'))
cevap = s.recv(bufLen).decode('utf-8')

seq = seq + 1

# Önizleme
print(mesaj)
print(cevap)


#
# Gelen mesajdan yayın kanalını çek (SETUP komutuna özel bu adres gönderilecek)
#
kanal = handshake.kanalCek(cevap)
adres = rtspAdres + "/" + kanal[0]

print("*"*30)
print("SETUP adresi: " + adres)
print("*"*30 + "\n")


#
# Gelen mesah içindeki video parametrelerini çek
#
rtpmap = handshake.videoParams(cevap)[0]
videoinfo = handshake.videoParams(cevap)[1]
fmtp = handshake.videoParams(cevap)[2]
sprop = handshake.videoParams(cevap)[3]

#
# Sprop parameters içindeki SPS ve PPS bölümlerini alalım
#
sprop = sprop.split(',')
sps = base64.decodebytes(sprop[0].encode())
pps = base64.decodebytes(sprop[1].encode())

print("*"*30)
print(sps)
print(pps)
print("*"*30)

print("*"*30)
print("Rtpmap:" , rtpmap)
print("Video info:" , videoinfo)
print("Fmtp:" , fmtp)
print("sprop:" , sprop)
print("*"*30 + "\n")
#
# 
# ******************************************************************************************************************* SETUP 
#
#

if(isAuth):
    if(isBasic):
        authSeq = auth.basicAuth(kullanici,sifre)
    elif(isDigest):
        authSeq = auth.digestAuth(realm,nonce,kullanici,sifre,"SETUP",uri)
    else:
        print('!! Authentication ile ilgili bir problem var !!\n')
        sys.exit()
else:
    authSeq = ""


mesaj = handshake.msg_SETUP(adres,seq,userAgent,authSeq,clientports)
gonder = s.send(mesaj.encode('utf-8'))
cevap = s.recv(bufLen).decode('utf-8')

seq = seq + 1

# Önizleme
print(mesaj)
print(cevap)


#
# Gelen mesah içindeki session id parametresini çek
#
sessionId = handshake.sesID(cevap)

print("*"*30)
print("Session ID: " + sessionId)
print("*"*30 + "\n")
#
# 
# ******************************************************************************************************************* OPTIONS 
#
#

if(isAuth):
    if(isBasic):
        authSeq = auth.basicAuth(kullanici,sifre)
    elif(isDigest):
        authSeq = auth.digestAuth(realm,nonce,kullanici,sifre,"OPTIONS",uri)
    else:
        print('!! Authentication ile ilgili bir problem var !!\n')
        sys.exit()
else:
    authSeq = ""


mesaj = handshake.msg_OPTIONS(rtspAdres,seq,userAgent,sessionId,authSeq)
gonder = s.send(mesaj.encode('utf-8'))
cevap = s.recv(bufLen).decode('utf-8')

seq = seq + 1

# Önizleme
print(mesaj)
print(cevap)
#
# 
# ******************************************************************************************************************* PLAY 
#
#

if(isAuth):
    if(isBasic):
        authSeq = auth.basicAuth(kullanici,sifre)
    elif(isDigest):
        authSeq = auth.digestAuth(realm,nonce,kullanici,sifre,"PLAY",uri)
    else:
        print('!! Authentication ile ilgili bir problem var !!\n')
        sys.exit()
else:
    authSeq = ""


mesaj = handshake.msg_PLAY(rtspAdres,seq,userAgent,sessionId,authSeq)
gonder = s.send(mesaj.encode('utf-8'))
cevap = s.recv(bufLen).decode('utf-8')

seq = seq + 1

# Önizleme
print(mesaj)
print(cevap)
#
# *******************************************************************************************************************












# ************************ Socket Başlatıyoruz ***********************************************************************
#
# Bu socket sunucudan gelen UDP paketlerini dinleyecek

try:
    s1 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s1.settimeout(timeout)
    s1.bind(("",int(clientports[0]))) 
except socket.timeout:
    print('!! Server yanıt vermedi !!')

#
# *******************************************************************************************************************






# ************************ Gelen UDP paketlerini analiz ederek dosyaya kaydediyoruz *********************************
#

with open(fname,'wb') as f:

    # Dosyamızın en başına SPS ve PPS verilerini ekleyelim
    startbytes = b"\x00\x00\x00\x01"
    f.write(startbytes+sps)
    f.write(startbytes+pps)

    # Artık geri kalan verileri dosyanın devamına yazabiliriz
    for i in range(rn):
        UDPpaketi = s1.recv(bufLen)    

        print("-"*30)
        sonuc = packetHandler.analiz(UDPpaketi)
        print("-"*30)



        if sonuc is not 0:
            print("capture",len(UDPpaketi),"bytes")
            print("dumping",len(sonuc),"bytes")
            f.write(sonuc)
        else:
            print("!"*30,"Bilinmeyen veri tipi")



s.close()
s1.close()
#
# *******************************************************************************************************************