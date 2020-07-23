#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 23 21:42:07 2020

@author: Zhengyi Xiao
"""

IPV4Fields=['Version','Header Length','Differentiated Services Fields:','Totoal Length','Identifier','Flags:','Fragment Offset','Time To Live','Protocol','Header checksum','Source IP Address','Destination IP Address']
ECNField=['Not-ECT','ECT(1)','ECT(0)','CE']
IPV4Flags=['Reserved: ','Don\' fragments: ','More fragments: ']
udpFields=['Source Port','Destination Port','Length','Checksum']
tcpFields=['Source Port','Destination Port','Sequence Number','Acknowledgment number','Header Length','Urgent','Acknowledgment','Push','Reset','Syn','Fin','Window Size','Checksum','Urgent Pointer']
tcpOptions=['End of Option List','No-Operation','Maximum Segment Size:','Window Scale:','SACK Permitted:','SACK:','Echo:','Echo Reply','Time Stamp Option:','Partial Order Connection Permitted:','Partial Order Service Profile:','CC','CC.New','CC.EECHO','TCP Alternative Checksum Request:','TCP Alternative Checksum Data:']
Option14=['TCP checksum','8-bit Fletcher\'s algorithm','16-bit Fletcher\'s algorithm','Redundant Checksum Avoidance']


def convertFormat(fr):
    return fr

def EthernetHandler(packet):
    return

def IPHandler(packet):
    if(int(packet[0],16)>>4==4):
        return IPV4Helper(packet)
    else:
        return IPV6Helper(packet)

def IPV6Helper(packet):
    IPHeader=['****** Internet Protocol Version 6 *********']

    return IPHeader,protocol,lenHeader

def IPV4Helper(packet):
    IPHeader=['****** Internet Protocol Version 4 *********']
    IPHeader.append(IPV4Fields[0]+': 0x'+str(bin(int(packet[0],16)>>4))+' (Version '+str(int(packet[0],16)>>4) +')')
    IPHeader.append(IPV4Fields[1]+': 0x'+str(bin((int(packet[0],16)<<4&255)>>4))+' ('+str(((int(packet[0],16)<<4&255)>>4)*4) +' bytes)')
    lenHeader=((int(packet[0],16)<<4&255)>>4)*4
    IPHeader.append(IPV4Fields[2])
    IPHeader.append(['Differentiated Services Fields'+str(bin(int(packet[1],16)>>2))+' ('+str(int(packet[1],16)>>2) +')'])
    IPHeader.append(['Congestion Notification'+': 0x'+str(bin((int(packet[1],16)<<6&255)>>6))+' ('+ECNField[(int(packet[1],16)<<6&255)>>6] +')'])

    IPHeader.append(IPV4Fields[3]+': 0x'+str(''.join(packet[2:4]))+' ('+str(int(''.join(packet[2:4]),16))+' bytes)')
    IPHeader.append(IPV4Fields[4]+': 0x'+str(''.join(packet[4:6]))+' ('+str(int(''.join(packet[4:6]),16))+')')
    IPHeader.append(IPV4Fields[5])
    bitWise=bin(int(''.join(packet[6:8]),16))[2:].zfill(16)
    IPHeader.append([IPV4Flags[0]+bitWise[0],IPV4Flags[1]+bitWise[1],IPV4Flags[2]+bitWise[2]])
    bitWise=bitWise[3:]
    IPHeader.append(IPV4Fields[6]+': 0x'+str(hex(int(bitWise,2)))+' ('+str(int(bitWise,2))+')')

    IPHeader.append(IPV4Fields[7]+': 0x'+str(packet[8])+' ('+str(int(packet[8],16))+')')
    protocol=int(packet[9],16)
    if(protocol==17):
        IPHeader.append(IPV4Fields[8]+': 0x'+str(packet[9])+' (UDP)')
    else:
        IPHeader.append(IPV4Fields[8]+': 0x'+str(packet[9])+' (TCP)')
    IPHeader.append(IPV4Fields[9]+': 0x'+str(''.join(packet[10:12])))

    IPHeader.append(IPV4Fields[10]+': 0x'+str(''.join(packet[12:16]))+' ('+str(int(packet[12],16))+'.'+str(int(packet[13],16))+'.'+str(int(packet[14],16))+'.'+str(int(packet[15],16))+')')
    IPHeader.append(IPV4Fields[11]+': 0x'+str(''.join(packet[16:20]))+' ('+str(int(packet[16],16))+'.'+str(int(packet[17],16))+'.'+str(int(packet[18],16))+'.'+str(int(packet[19],16))+')')
    return IPHeader,protocol,lenHeader


def udpHandler(segment):
    udpHeader=['****** User Datagram Protocol *************']
    ##Standard UDP Fields
    udpHeader.append(udpFields[0]+': 0x'+str(''.join(segment[0:2]))+' ('+str(int(''.join(segment[0:2]),16))+')')
    udpHeader.append(udpFields[1]+': 0x'+str(''.join(segment[2:4]))+' ('+str(int(''.join(segment[2:4]),16))+')')
    udpHeader.append(udpFields[2]+': 0x'+str(''.join(segment[4:8]))+' ('+str(int(''.join(segment[4:8]),16))+')')
    lenHeader=int(''.join(segment[4:8]),16)
    udpHeader.append(udpFields[3]+': 0x'+str(''.join(segment[8:12])))

    return udpHeader,lenHeader

def tcpHandler(segment):
    tcpHeader=['****** Transmission Control Protocol ******']
    ##Standard TCP Fields
    tcpHeader.append(tcpFields[0]+': 0x'+str(''.join(segment[0:2]))+' ('+str(int(''.join(segment[0:2]),16))+')')
    tcpHeader.append(tcpFields[1]+': 0x'+str(''.join(segment[2:4]))+' ('+str(int(''.join(segment[2:4]),16))+')')
    tcpHeader.append(tcpFields[2]+': 0x'+str(''.join(segment[4:8]))+' ('+str(int(''.join(segment[4:8]),16))+')')
    tcpHeader.append(tcpFields[3]+': 0x'+str(''.join(segment[8:12]))+' ('+str(int(''.join(segment[8:12]),16))+')')

    bitWise=bin(int(''.join(segment[12:13]),16))[2:].zfill(8)+bin(int(''.join(segment[13:14]),16))[2:].zfill(8)
    tcpHeader.append(tcpFields[4]+': '+hex(int(''.join(bitWise[:4]),2))+'('+str(int(32*int(''.join(bitWise[:4]),2)/8))+' bytes)')
    lenHeader=int(32*int(''.join(bitWise[:4]),2)/8)
    bitWise=bitWise[-6:]

    ##TCP Tags
    tcpHeader.append(['Tags:'])
    for i in range(6):
        if(bitWise[i] == '1'):
            tcpHeader[-1].append(tcpFields[i+5]+': 1')
    tcpHeader.append(tcpFields[11]+': '+str(int(''.join(segment[14:16]),16)))
    tcpHeader.append(tcpFields[12]+': 0x'+str(''.join(segment[16:18])))
    tcpHeader.append(tcpFields[13]+': '+str(int(''.join(segment[18:20]),16)))

    ##TCP Options
    count=20
    if(count >= len(segment)):
        return tcpHeader,lenHeader
    tcpHeader.append(['Options:'])
    while count < len(segment):
        i=int(segment[count],16)
        if(i < 2 or (i>10 and i<14)):
            tcpHeader[-1].append(tcpOptions[i])
            count=count+1
        else:
            length=int(segment[count+1],16)
            if(i==2):
                value=''.join(segment[count+2:count+length])
                tcpHeader[-1].append(tcpOptions[i]+': '+value+' ('+str(int(value,16))+' bytes)')
            if(i==3):
                value=''.join(segment[count+2:count+length])
                tcpHeader[-1].append(tcpOptions[i]+': '+str(int(value,16))+' (multiply by'+str(pow(2,int(value,16)))+')')
            if(i==4 or i==9):
                tcpHeader[-1].append(tcpOptions[i]+': 1')
            if(i==5):
                lEdge=''.join(segment[count+2:count+2+int((length-2)/2)])
                rEdge=''.join(segment[count+2+int((length-2)/2):count+length])
                tcpHeader[-1].append(tcpOptions[i])
                tcpHeader[-1].append(['Left Edge: 0x'+lEdge+' ('+str(int(lEdge,16))+')','Right Edge: 0x'+rEdge+' ('+str(int(rEdge,16))+')'])
            if(i==8):
                TSvalue=''.join(segment[count+2:count+6])
                TEvalue=''.join(segment[count+6:count+10])
                tcpHeader[-1].append(tcpOptions[i])
                tcpHeader[-1].append(['Time Stamp Value: 0x'+TSvalue+' ('+str(int(TSvalue,16))+')','Time Echo Reply Value: 0x'+TEvalue+' ('+str(int(TEvalue,16))+')'])
            if(i==10):
                value=''.join(segment[count+2:count+length])
                bitWise=bin(int(value,16))[2:].zfill(8)
                tcpHeader[-1].append(tcpOptions[i])
                tcpHeader[-1].append(['Start Flag: '+str(bitWise[0]),'End Flag'+str(bitWise[1])])
            if(i==14):
                value=''.join(segment[count+2:count+length])
                tcpHeader[-1].append(tcpOptions[i]+': '+value+' ('+Option14[int(value)]+')')
            if(i==15):
                value=''.join(segment[count+2:count+length])
                tcpHeader[-1].append(tcpOptions[i]+': '+value)
            count=count+length
    return tcpHeader,lenHeader

def httpHandler(data):
    start=0
    httpHeader=["****** Hypertext Transfer Protocol *******"]
    for i in range(len(data)):
        if(data[i]=='0d' and data[i+1]=='0a'):
            httpHeader.append(bytearray.fromhex(''.join(data[start:i])).decode())
            start=i+2
        if(data[i]=='0d' and data[i+1]=='0a' and data[i+2]=='0d' and data[i+3]=='0a'):
            return httpHeader
    return httpHeader

def print_list(items, level=0):
    for item in items:
        if isinstance(item, list):
            print_list(item, level + 1)
        else:
            if level != 0:
                indentation = '    ' * level + '\_ '
            else:
                indentation = '__ '
            print('%s%s' % (indentation, item))

def main():
    f = open("tcp.txt", "r")
    packet = f.read().split()
    f.close()


    header,protocol,lenHeader = IPHandler(packet)
    print(header[0])
    print_list(header[1:],0)
    print()

    packet=packet[lenHeader:]
    if(protocol==17):
        header,lenHeader=udpHandler(packet)
    else:
        header,lenHeader=tcpHandler(packet)
    print(header[0])
    print_list(header[1:],0)
    print()

    packet=packet[lenHeader:]
    header=httpHandler(packet)
    print(header[0])
    print_list(header[1:],0)

if __name__ == "__main__":
    main()