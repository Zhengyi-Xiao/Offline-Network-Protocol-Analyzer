#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 23 21:42:07 2020

@author: Zhengyi Xiao
"""
EthernetFields=['Destination','Source','Type']
IPV4Fields=['Version','Header Length','Differentiated Services Fields:','Totoal Length','Identifier','Flags:','Fragment Offset','Time To Live','Protocol','Header checksum','Source IP Address','Destination IP Address']
ECNField=['Not-ECT','ECT(1)','ECT(0)','CE']
IPV4Flags=['Reserved: ','Don\' fragments: ','More fragments: ']
udpFields=['Source Port','Destination Port','Length','Checksum']
tcpFields=['Source Port','Destination Port','Sequence Number','Acknowledgment number','Header Length','Urgent','Acknowledgment','Push','Reset','Syn','Fin','Window Size','Checksum','Urgent Pointer']
tcpOptions=['End of Option List','No-Operation','Maximum Segment Size:','Window Scale:','SACK Permitted:','SACK:','Echo:','Echo Reply','Time Stamp Option:','Partial Order Connection Permitted:','Partial Order Service Profile:','CC','CC.New','CC.EECHO','TCP Alternative Checksum Request:','TCP Alternative Checksum Data:']
Option14=['TCP checksum','8-bit Fletcher\'s algorithm','16-bit Fletcher\'s algorithm','Redundant Checksum Avoidance']

## Missisng IPv6, IPv4 Options, UI, and convertFormat
def convertFormat(fr):
    for i in fr:
        if(len(i)>2):
            fr.remove(i)
    return fr

def EthernetHandler(frame):
    EthernetHeader=['**************** Ethernet II ***************']
    EthernetHeader.append(EthernetFields[0]+': 0x'+str(''.join(frame[0:6]))+' ('+str(int(frame[0],16))+'.'+str(int(frame[1],16))+'.'+str(int(frame[2],16))+'.'+str(int(frame[3],16))+'.'+str(int(frame[4],16))+'.'+str(int(frame[5],16))+')')
    EthernetHeader.append(EthernetFields[1]+': 0x'+str(''.join(frame[6:12]))+' ('+str(int(frame[6],16))+'.'+str(int(frame[7],16))+'.'+str(int(frame[8],16))+'.'+str(int(frame[9],16))+'.'+str(int(frame[10],16))+'.'+str(int(frame[11],16))+')')
    protocol=int(''.join(frame[12:14]),16)
    if(protocol==2048): #IPv4
        EthernetHeader.append(EthernetFields[1]+': 0x'+str(''.join(frame[12:14]))+' (IPv4)')
    else:               #IPv6
        EthernetHeader.append(EthernetFields[1]+': 0x'+str(''.join(frame[12:14]))+' (IPv6)')
    return EthernetHeader

def IPHandler(packet):
    if(int(packet[0],16)>>4==4):
        return IPv4Handler(packet)
    else:
        return IPv6Handler(packet)

def IPv4Handler(packet):
    ##Standard ipv4 Fields
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

    ##ipv4 options
    return IPHeader,protocol,lenHeader

def IPv6Handler(packet):
    IPHeader=['****** Internet Protocol Version 6 *********']

    return IPHeader,protocol,lenHeader

def transportHandler(segment,protocol):
    if(protocol==17):
        return udpHandler(segment)
    else:
        return tcpHandler(segment)

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

    count=20
    if(lenHeader >= count):
        return tcpHeader,lenHeader
    ##TCP Options
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

def print_list_helper(items, level=0):
    for item in items:
        if isinstance(item, list):
            print_list_helper(item, level + 1)
        else:
            if level != 0:
                indentation = '    ' * level + '\_ '
            else:
                indentation = '__ '
            print('%s%s' % (indentation, item))

def print_list(header):
    print(header[0])
    print_list_helper(header[1:],0)
    print()

def main():
    f = open("tcp.txt", "r")
    frame = convertFormat(f.read().split())
    f.close()
    
    ## Ethernet Layer
    header=EthernetHandler(frame)
    print_list(header)

    ## IP Layer
    packet=frame[14:]
    header,protocol,lenHeader = IPHandler(packet)
    print_list(header)

    ## Transport Layer
    segment=packet[lenHeader:]
    header,lenHeader=transportHandler(segment,protocol)
    print_list(header)

    ## Application Layer
    data=segment[lenHeader:]
    if(len(data)>0):
        header=httpHandler(data)
        print_list(header)

if __name__ == "__main__":
    main()