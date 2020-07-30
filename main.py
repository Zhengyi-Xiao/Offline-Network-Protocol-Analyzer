#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 23 21:42:07 2020

@author: Zhengyi Xiao
"""
import sys
import os

from multiprocessing import Process, Lock, Pool, Value

EthernetFields=['Destination','Source','Type']
IPv4Fields=['Version','Header Length','Differentiated Services Fields:','Totoal Length','Identifier','Flags:','Fragment Offset','Time To Live','Protocol','Header checksum','Source IP Address','Destination IP Address']
ECNField=['Not-ECT','ECT(1)','ECT(0)','CE']
IPv4Flags=['Reserved: ','Don\' fragments: ','More fragments: ']
IPv4Options=['End of Options List','No Operation','Record Route(RR)','Tame Stamp(TS)','Loose Routing','Strict Routing']
udpFields=['Source Port','Destination Port','Length','Checksum']
tcpFields=['Source Port','Destination Port','Sequence Number','Acknowledgment number','Header Length','Urgent','Acknowledgment','Push','Reset','Syn','Fin','Window Size','Checksum','Urgent Pointer']
tcpOptions=['End of Option List','No-Operation','Maximum Segment Size:','Window Scale:','SACK Permitted:','SACK:','Echo:','Echo Reply','Time Stamp Option:','Partial Order Connection Permitted:','Partial Order Service Profile:','CC','CC.New','CC.EECHO','TCP Alternative Checksum Request:','TCP Alternative Checksum Data:']
Option14=['TCP checksum','8-bit Fletcher\'s algorithm','16-bit Fletcher\'s algorithm','Redundant Checksum Avoidance']

def frameAnalyzer(lines):
    frame=list()
    for i in range(len(lines)):
        line=lines[i].split()
        # if the leading is not an offset, the line will be ignored.
        if(len(line[0])<2):
            continue
        # find the offset of current line by subtracting the next offset from the current
        if(not i==len(lines)-1):
            nextLineOffset=int(lines[i+1].split()[0],16)
            offset=nextLineOffset-int(line[0],16)
        else:
            offset=len(line)
        # if the length of the line smaller than expected and it is not the
        # last line of a trace, then it is a currupted line and exit the program.
        if(len(line[1:])<offset and not i==(len(lines)-1)):
            sys.exit('Error: Corrupted Line ('+str(line[0])+')')
        frame=frame+line[1:offset+1]

    for i in range(len(frame)):
        frame[i]=frame[i].lower()
    return frame

def traceAnalyzer(lines):
    frame=list()
    for line in lines:
        line=line.split()
        if(len(line)<=1):
            continue
        try:
            offset=int(line[0],16)
            if(offset==0):
                frame.append([])
        except ValueError:
            continue
        frame[-1].append(' '.join(line))
    return frame

def interpreter(num,lock,frames):
    frame=frameAnalyzer(frames)
    ## Ethernet Layer
    EthernetHeader=EthernetHandler(frame)

    ## IP Layer
    packet=frame[14:]
    IPHeader,protocol,lenHeader,lenPacket = IPHandler(packet)

    ## Transport Layer
    segment=packet[lenHeader:lenPacket]
    TransportHeader,lenHeader=transportHandler(segment,protocol)

    ## Application Layer
    data=segment[lenHeader:]
    APPheader=[]
    if(len(data)>0):
        APPheader=httpHandler(data)
    lock.acquire()
    print('PACKET: '+str(num.value))
    num.value=num.value+1
    header=EthernetHeader+IPHeader+TransportHeader+APPheader
    print_list(header)
    lock.release()

def EthernetHandler(frame):
    EthernetHeader=['**************** Ethernet II ***************']
    EthernetHeader.append(EthernetFields[0]+': 0x'+str(':'.join(frame[0:6]))+' ('+str(int(frame[0],16))+'.'+str(int(frame[1],16))+'.'+str(int(frame[2],16))+'.'+str(int(frame[3],16))+'.'+str(int(frame[4],16))+'.'+str(int(frame[5],16))+')')
    EthernetHeader.append(EthernetFields[1]+': 0x'+str(':'.join(frame[6:12]))+' ('+str(int(frame[6],16))+'.'+str(int(frame[7],16))+'.'+str(int(frame[8],16))+'.'+str(int(frame[9],16))+'.'+str(int(frame[10],16))+'.'+str(int(frame[11],16))+')')
    protocol=int(''.join(frame[12:14]),16)
    if(protocol==2048): #IPv4
        EthernetHeader.append(EthernetFields[2]+': 0x'+str(''.join(frame[12:14]))+' (IPv4)')
    else:               #IPv6
        EthernetHeader.append(EthernetFields[2]+': 0x'+str(''.join(frame[12:14]))+' (IPv6)')
    return EthernetHeader

def IPHandler(packet):
    if(int(packet[0],16)>>4==4):
        return IPv4Handler(packet)
    else:
        return IPv6Handler(packet)

def IPv4Handler(packet):
    ##Standard IPv4 Fields
    IPHeader=['****** Internet Protocol Version 4 *********']
    IPHeader.append(IPv4Fields[0]+': 0x'+str(bin(int(packet[0],16)>>4))+' (Version '+str(int(packet[0],16)>>4) +')')
    IPHeader.append(IPv4Fields[1]+': 0x'+str(bin((int(packet[0],16)<<4&255)>>4))+' ('+str(((int(packet[0],16)<<4&255)>>4)*4) +' bytes)')
    lenHeader=((int(packet[0],16)<<4&255)>>4)*4
    IPHeader.append(IPv4Fields[2])
    IPHeader.append(['Differentiated Services Fields: '+str(bin(int(packet[1],16)>>2)[2:])+' ('+str(int(packet[1],16)>>2) +')'])
    IPHeader.append(['Congestion Notification'+': '+str(bin((int(packet[1],16)<<6&255)>>6)[2:])+' ('+ECNField[(int(packet[1],16)<<6&255)>>6] +')'])

    IPHeader.append(IPv4Fields[3]+': 0x'+str(''.join(packet[2:4]))+' ('+str(int(''.join(packet[2:4]),16))+' bytes)')
    lenPacket=int(''.join(packet[2:4]),16)
    IPHeader.append(IPv4Fields[4]+': 0x'+str(''.join(packet[4:6]))+' ('+str(int(''.join(packet[4:6]),16))+')')
    IPHeader.append(IPv4Fields[5])
    bitWise=bin(int(''.join(packet[6:8]),16))[2:].zfill(16)
    IPHeader.append([IPv4Flags[0]+bitWise[0],IPv4Flags[1]+bitWise[1],IPv4Flags[2]+bitWise[2]])
    bitWise=bitWise[3:]
    IPHeader.append(IPv4Fields[6]+': 0x'+str(hex(int(bitWise,2)))+' ('+str(int(bitWise,2))+')')

    IPHeader.append(IPv4Fields[7]+': 0x'+str(packet[8])+' ('+str(int(packet[8],16))+')')
    protocol=int(packet[9],16)
    if(protocol==17):
        IPHeader.append(IPv4Fields[8]+': 0x'+str(packet[9])+' (UDP)')
    else:
        IPHeader.append(IPv4Fields[8]+': 0x'+str(packet[9])+' (TCP)')
    IPHeader.append(IPv4Fields[9]+': 0x'+str(''.join(packet[10:12])))

    IPHeader.append(IPv4Fields[10]+': '+str(':'.join(packet[12:16]))+' ('+str(int(packet[12],16))+'.'+str(int(packet[13],16))+'.'+str(int(packet[14],16))+'.'+str(int(packet[15],16))+')')
    IPHeader.append(IPv4Fields[11]+': '+str(':'.join(packet[16:20]))+' ('+str(int(packet[16],16))+'.'+str(int(packet[17],16))+'.'+str(int(packet[18],16))+'.'+str(int(packet[19],16))+')')

    if(lenHeader == 20):
        return IPHeader,protocol,lenHeader,lenPacket
    #IPv4 options
    IPHeader.append('Option(s)')
    options=list()
    count=20
    #if(packet[count]=='00'):
    #if(packet[count]=='01'):
    # Record Route(RR)
    if(packet[count]=='07'):
        options.append(IPv4Options[2])
        options.append(['Length: 0x'+str(packet[21])+' ('+str(int(packet[21],16))+')'])
        options[-1].append('Pointer: 0x'+str(packet[22])+' ('+str(int(packet[22],16))+')')
        options[-1].append('Router(s)')
        router=list()
        count=23
        while count < 23+(int(packet[22],16))-4:
            router.append('Router'+str(len(router)+1)+': '+str(':'.join(packet[count:count+4]))+' ('+str(int(packet[count],16))+'.'+str(int(packet[count+1],16))+'.'+str(int(packet[count+2],16))+'.'+str(int(packet[count+3],16))+')')
            count=count+4
        options[-1].append(router)
        count=20+int(packet[21],16)
    #if(packet[count]=='44'):
    #if(packet[count]=='83'):
    #if(packet[count]=='89'):
    IPHeader.append(options)
    return IPHeader,protocol,lenHeader,lenPacket

def IPv6Handler(packet):
    IPHeader=['****** Internet Protocol Version 6 *********']
    ## Not needed for this project
    protocol=list()
    lenHeader=0
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
    tcpHeader.append('Tags:')
    tags=list()
    for i in range(6):
        if(bitWise[i] == '1'):
            tags.append(tcpFields[i+5]+': 1')
    tcpHeader.append(tags)
    tcpHeader.append(tcpFields[11]+': '+str(int(''.join(segment[14:16]),16)))
    tcpHeader.append(tcpFields[12]+': 0x'+str(''.join(segment[16:18])))
    tcpHeader.append(tcpFields[13]+': '+str(int(''.join(segment[18:20]),16)))

    count=20
    if(lenHeader <= count):
        return tcpHeader,lenHeader
    ##TCP Options
    tcpHeader.append('Options:')
    options=list()
    while count < len(segment):
        i=int(segment[count],16)
        if(i < 2 or (i>10 and i<14)):
            options.append(tcpOptions[i])
            count=count+1
        else:
            length=int(segment[count+1],16)
            if(i==2):
                value=''.join(segment[count+2:count+length])
                options.append(tcpOptions[i]+': '+value+' ('+str(int(value,16))+' bytes)')
            if(i==3):
                value=''.join(segment[count+2:count+length])
                options.append(tcpOptions[i]+': '+str(int(value,16))+' (multiply by'+str(pow(2,int(value,16)))+')')
            if(i==4 or i==9):
                options.append(tcpOptions[i]+': 1')
            if(i==5):
                lEdge=''.join(segment[count+2:count+2+int((length-2)/2)])
                rEdge=''.join(segment[count+2+int((length-2)/2):count+length])
                options.append(tcpOptions[i])
                options.append(['Left Edge: 0x'+lEdge+' ('+str(int(lEdge,16))+')','Right Edge: 0x'+rEdge+' ('+str(int(rEdge,16))+')'])
            if(i==8):
                TSvalue=''.join(segment[count+2:count+6])
                TEvalue=''.join(segment[count+6:count+10])
                options.append(tcpOptions[i])
                options.append(['Time Stamp Value: 0x'+TSvalue+' ('+str(int(TSvalue,16))+')','Time Echo Reply Value: 0x'+TEvalue+' ('+str(int(TEvalue,16))+')'])
            if(i==10):
                value=''.join(segment[count+2:count+length])
                bitWise=bin(int(value,16))[2:].zfill(8)
                options.append(tcpOptions[i])
                options.append(['Start Flag: '+str(bitWise[0]),'End Flag'+str(bitWise[1])])
            if(i==14):
                value=''.join(segment[count+2:count+length])
                options.append(tcpOptions[i]+': '+value+' ('+Option14[int(value)]+')')
            if(i==15):
                value=''.join(segment[count+2:count+length])
                options.append(tcpOptions[i]+': '+value)
            count=count+length
    tcpHeader.append(options)
    return tcpHeader,lenHeader

def httpHandler(data):
    start=0
    httpHeader=["****** Hypertext Transfer Protocol *******"]
    for i in range(len(data)):
        if(data[i]=='0d' and data[i+1]=='0a'):
            httpHeader.append(bytearray.fromhex(''.join(data[start:i])).decode())
            start=i+2
        if(data[i]=='0d' and data[i+1]=='0a' and data[i+2]=='0d' and data[i+3]=='0a'):
            httpHeader.append('File Data: '+str(len(data)-i-4)+' bytes')
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
            if(item[0] == '*'):
                print('%s%s' % ('', item))
            else:
                print('%s%s' % (indentation, item))

def print_list(header):
    print(header[0])
    print_list_helper(header[1:],0)
    print()

def main():
    try:
        if(len(sys.argv)==2):
            f = open(str(sys.argv[1]), 'r')
        else:
            print('The name of the trace file(with .txt): ',end='')
            userInput=input()
            f = open(userInput, 'r')
    except FileNotFoundError:
        sys.exit('File does not exist!')
    trace=f.readlines()
    f.close()

    frames=traceAnalyzer(trace)

    lock = Lock()
    num = Value('i', 0)
    for frame in frames:
        Process(target=interpreter, args=(num,lock, frame)).start()

if __name__ == '__main__':
    main()
