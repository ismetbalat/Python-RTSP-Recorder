# Gelen UDP paketlerini analiz ediyoruz

import bitstring, string


def analiz(UDPpacket):

    # İstatistikler
    count_sps = 0
    count_pps = 0
    count_unit = 0


    hex_veri = bitstring.BitArray(bytes=UDPpacket)
    startbytes = b"\x00\x00\x00\x01"


    ####################################### ÖRNEK ÇEVİRMELER ###################################################
    #
    #print("Orjinal: " , veri)                       # b'\x80\xe0U\x9d\x95-\xc74\x00\x00\xa0Fh\xee<\x80'
    #print("Orj Hex: " , hex_veri)                   # 0x80e0559c952dc7340000a046674d002a9da81e0089f966e020202040

    #print("Hex kırp: " , hex_veri[:2])              # 0b10
    #print("Integer: " , hex_veri[:2].uint)          # 2
    #
    ############################################################################################################


    # header Byte ve bit değerleri (1 Byte = 8 bit)
    # default fixed header 12 Byte uzunluktadır.

    lc=12 # bytecounter 
    bc=12*8 # bitcounter
    
    # Socket üzerinden UDP paketinin payload ı alınır. 
    # UDP header zaten sockete gelmez
    #
    # UDP packet  = | UDP header | UDP Payload |
    # UDP payload = | RTP header | RTP Payload |
    #
    # Örnek bir hamveri = b'\x80\xe0\xfb\x9e\xdcv\xca\x14\x00\x00\xa0Fh\xee<\x80'
    #
    # Alınan byte-array tipindeki ham veriyi hex formatındaki stringe çeviriyoruz

    version = hex_veri[0:2].uint # version
    p = hex_veri[3] # P
    x = hex_veri[4] # X
    cc = hex_veri[4:8].uint # CC
    m = hex_veri[9] # M
    pt = hex_veri[9:16].uint # PT
    sn = hex_veri[16:32].uint # sequence number
    timestamp = hex_veri[32:64].uint # timestamp
    ssrc = hex_veri[64:96].uint # ssrc identifier

    print("version, p, x, cc, m, pt",version,p,x,cc,m,pt)
    print("sequence number, timestamp",sn,timestamp)
    print("sync. source identifier",ssrc)

    # Güncel fixed header uzunluğu.
    # Henüz headeri uzatacak bir işlem olmadı
    lc=12 # bytecounter 
    bc=12*8 # bitcounter

    # RTP header detaylı bilgisi aşağıdaki adresten öğrenilebilir
    # https://en.wikipedia.org/wiki/Real-time_Transport_Protocol
    #
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |V=2|P|X|  CC   |M|     PT      |       sequence number         |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                           timestamp                           |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |           synchronization source (SSRC) identifier            |
    #  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    #  |            contributing source (CSRC) identifiers             |
    #  |                             ....                              |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |  profile-spec. ext. header ID |       sequence number         |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Extension header                      |
    #  |                             ....                              |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Özet olarak geçelim;
    #
    # version (V): 2 bits       =>  RTP versiyonunu tanımlar. Güncel versiyon (2) dir.
    #
    # padding (P): 1 bit        =>  Eğer (1) ayarlanmışsa payload verisi bittikten sonra ekstra bir veya birden fazla octet var demektir.
    #
    # extension (X): 1 bit      =>  Eğer (1) ayarlanmışsa sabit header ile payload arasında eksta bir header verisi daha var demektir.  
    #
    # CSRC count (CC): 4 bits   =>  CSRC sayımı, sabit başlığı takip eden CSRC identifiers sayısını içerir.
    #
    # marker (M): 1 bit         =>  Bir profil tarafından tanımlanır ve uygulama seviyesinde kullanılır. Eğer ayarlanırsa uygulama için o andaki verinin uygulamayla ilgili bazı özel durumlara sahip olduğunu belirtir. Örneğin 1 ayarlıysa video frameninin sonunun geldiğini gösterir.
    #
    # payload type (PT): 7 bits =>  Payload formatını gösterir. Ve uygulama tarafından onun yorumlanmasına karar verilir. Bir RTP profili tarafından belirtilir. Örneğin minimal kontrol ile ses ve video konferansları.
    #
    # sequence number: 16 bits  =>  Sıra numarası RTP başlığında paket kaybını belirlemeye yarayan ve aynı tarih bilgisi değerine sahip paketlerin sıralanmasını sağlar. Ve başlangıç değeri rastgele olarak belirlenir.
    #
    # timestamp: 32 bits        =>  Başlangıcı rastgele olan ve gecikme ile jitter i hesaplamada kullanılan zaman bilgisi verisi.
    #
    # SSRC: 32 bits             =>  Senkronizasyon kaynak tanımlayıcıları, tek bir şekilde bir streamin kaynağını tanımlar. aynı RTP oturumu içindeki senkronizasyon kaynağı tek ve eşsiz olmalıdır. Bu tanımlayıcı rastgele seçilir.
    #
    # CSRC list: 32 bits        =>  Yardımcı kaynak idleri birçok kaynaktan oluşturulan bir stream için yardımcı kaynakları numaralandırır.
    

    


    # cc değerini kontrol ediyoruz
    # cc sayısı kadar CSRC vardır
    # her bir CSRC 32 bit uzunluktadır
    # her okuduğumuz csrc identifiers verisi için header uzunluğunu artıracağız
    # lc ye +4 eklenecek (32 bits 4 bytes eder)
    # bc ye +32 eklenecek (her csrc 32 bit)
    cids=[]
    for i in range(cc):
        CSRC_veri = hex_veri[bc:bc+32].uint
        cids.append(CSRC_veri)
        
        # header uzunluğunu güncelle
        bc+=32 
        lc+=4

    print("csrc identifiers:",cids)




    # x değerini kontrol ediyoruz
    # extension (X) eğer (1) ayarlanmışsa fixed header ile payload arasında eksta bir header verisi daha var demektir.
    # profile-spec. ext. header ID verisi 16 byte dır
    # ext header len verisi 16 byte dır
    # ext header len x 32 byte kadar ekstra header verisi vardır
    if (x):
        # profile-spec. ext. header ID
        hid = hex_veri[bc:bc+16].uint       

        # header uzunluğunu güncelle
        bc+=16
        lc+=2

        # header len
        hlen = hex_veri[bc:bc+16].uint      

        # header uzunluğunu güncelle
        bc+=16
        lc+=2

        print("ext. header id, header len",hid,hlen)

        # Extension headerin uzunluğu ile header uzunluğunu güncelle
        ext_header = hex_veri[bc:bc+32*hlen]        

        # header uzunluğunu güncelle
        bc+=32*hlen 
        lc+=4*hlen
    






    # Payload verisine yani NAL paketine giriyoruz artık.
    # 
    # https://tools.ietf.org/html/rfc6184#section-1.3
    #
    # Daha detaylı bilgi için: https://tools.ietf.org/html/rfc6184#section-5.2
    #
    """
    5.3. NAL Unit Header Usage
    NAL unit header yapısı dökümanda gösterildiği gibi F, NRI ve Type dan oluşur.
    Section 1.3.  NAL unit header aşağıdaki gibidir.
        +---------------+
        |0|1|2|3|4|5|6|7|
        +-+-+-+-+-+-+-+-+
        |F|NRI|  Type   |
        +---------------+
    This section specifies the semantics of F and NRI according to this
    specification.    
    """
    #
    # F: 1 bit      => forbidden_zero_bit. Aktarım esnasında bir hata olup olmadığını gösterir. (0) değeri normal, (1) değeri syntax ihlali olduğunu gösterir. Yani 0 olmalıdır.
    #
    # NRI: 2 bits   => nal_ref_idc. Sonraki 2 bit, bu NAL biriminin bir reference field/frame/picture olup olmadığını gösterir. Yani (0) tahmin paketidir, videoda kullanılmaz. (0) dan büyük bir değerse bu NAL paketi  reference field/frame/picture den biridir. 
    #
    # Type: 5 bits  =>  nal_unit_type. NAL unitin tipini belli eder. Tablodan bakabilirsiniz.
    #
    """
    Table 3.  Her paketteki NAL unit type değerleri
                mode (yes = allowed, no = disallowed, ig = ignore)
        Payload Packet    Single NAL    Non-Interleaved    Interleaved
        Type    Type      Unit Mode           Mode             Mode
        -------------------------------------------------------------
        0      reserved      ig               ig               ig
        1-23   NAL unit     yes              yes               no
        24     STAP-A        no              yes               no
        25     STAP-B        no               no              yes
        26     MTAP16        no               no              yes
        27     MTAP24        no               no              yes
        28     FU-A          no              yes              yes
        29     FU-B          no               no              yes
        30-31  reserved      ig               ig               ig
    """
    #
    # Aşağıdaki linkten detaylı bilgi alabilirsiniz:
    # http://stackoverflow.com/questions/7665217/how-to-process-raw-udp-packets-so-that-they-can-be-decoded-by-a-decoder-filter-i
    # Özetle:
    #
    """
    H264 FRAGMENT
    First byte:  [ 3 NAL UNIT BITS | 5 FRAGMENT TYPE BITS] 
    Second byte: [ START BIT | END BIT | RESERVED BIT | 5 NAL UNIT BITS] 
    Other bytes: [... VIDEO FRAGMENT DATA...]
    """

    # First Byte kontrolü yapılır
    fb = hex_veri[bc]                                      # i.e. "F"
    nri = hex_veri[bc+1:bc+3].uint                         # "NRI"
    nlu0 = hex_veri[bc:bc+3]                               # "3 NAL UNIT BITS" (i.e. [F | NRI])
    typ = hex_veri[bc+3:bc+8].uint                         # "Type"

    print("F, NRI, Type :", fb, nri, typ)
    print("first three bits together :",nlu0)


    

    # Tipe göre verinin türünü ayırt edeceğiz
    if (typ >= 1 and typ <= 23):
        # Tip 7 veya 8 ise bu paket SPS veya PPS paketidir.
        # Bu paket resolution, vb. meta bilgiler sunar
        # İlk paketi tamamen alabiliriz
        # Detay için bakabilirsiniz:
        # https://www.cardinalpeak.com/the-h-264-sequence-parameter-set/
        if (typ==7):
            print(">>>>> SPS packet")
            count_sps += 1
        elif (typ==7):
            print(">>>>> PPS packet")
            count_pps += 1
        else:
            print(">>>>> nal unit")
            count_unit += 1
        return startbytes+UDPpacket[lc:],[count_sps,count_pps,count_unit],1
        # Burada NAL başlangıç dizisi "startbytes" a  "First byte" ı eklediğimize dikkat edin.  


    # header uzunluğunu güncelle
    bc+=8 
    lc+=1






    # ********* Artık "Second byte" kısmındayız ************
    # "Type" değeri genelde 28 gibi bir değerdir, i.e. "FU-A"
    # Second Byte kontrolü yapılır
    start = hex_veri[bc] # start bit
    end = hex_veri[bc+1] # end bit
    reserved = hex_veri[bc+2] # end bit
    nlu1 = hex_veri[bc+3:bc+8] # 5 nal unit bits


    print("start, end, reserved, nlu1 :", start, end, reserved, nlu1)



    if (start):                                 # Video frame inin başlangıcı
        print(">>> first fragment found")
        nlu=nlu0+nlu1                           # birinci ve ikinci byte içindeki NAL unit bitleri
        head=startbytes+nlu.bytes               # NAL verisinin başlangıcı (startbytes + nal unit bits)
        lc+=1                                   # "Second byte" kısmını geçiyoruz
    elif (start==False and end==False):         # Akıştaki orta seviye fragmenttir, sadece "VIDEO FRAGMENT DATA" yı alıyoruz
        head=b""
        lc+=1                                   # "Second byte" kısmını geçiyoruz
    elif (end):                                 # Akıştaki son fragmenttir, sadece "VIDEO FRAGMENT DATA" yı alıyoruz
        head=b""
        print("<<<< last fragment found")
        lc+=1                                   # "Second byte" kısmını geçiyoruz
    else:
        pass



    # Son özet olarak H264 paketi şu şekilde birleştirilir:
    # H264: 0x000001[SPS], 0x000001[PPS], 0x000001[VIDEO FRAME], 0x000001...
    # MPEG4: 0x000001[Visual Object Sequence Start], 0x000001[VIDEO FRAME]
    #
    # SPS veya PPS gördüğümüzde yukarıda başına startbytes ekleyerek paketi sonlandırdık.
    # Diğer paketler içinde bir yukarıda başına startbytes ekleyerek birleştirdik



    # Other Bytes yani "Video Fragment Data" alınır
    if (typ==28):                                                       # Bu program şimdilik sadece "Type" = 28, i.e. "FU-A" için çalışıyor.  
        return head+UDPpacket[lc:],[count_sps,count_pps,count_unit],0
    else:                                                               # Şimdilik bunun için üzgünüz :(
        return 0,[count_sps,count_pps,count_unit],0                 
