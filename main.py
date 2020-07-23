#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 23 21:42:07 2020

@author: zhengyixiao
"""


udpFields=['Source Port','Destination Port','Length','Checksum']
tcpFields=['Source Port','Destination Port','Sequence Number','Acknowledgment number','Header Length','Urgent','Acknowledgment','Push','Reset','Syn','Fin','Window Size','Checksum','Urgent Pointer']
tcpOptions=['End of Option List','No-Operation','Maximum Segment Size:','Window Scale:','SACK Permitted:','SACK:','Echo:','Echo Reply','Time Stamp Option:','Partial Order Connection Permitted:','Partial Order Service Profile:','CC','CC.New','CC.EECHO','TCP Alternative Checksum Request:','TCP Alternative Checksum Data:']
Option14=['TCP checksum','8-bit Fletcher\'s algorithm','16-bit Fletcher\'s algorithm','Redundant Checksum Avoidance']

def udpHandler(segment):
    udpHeader=['****** User Datagram Protocol *************']
    ##Standard UDP Fields
    udpHeader.append(udpFields[0]+': 0x'+str(''.join(segment[0:2]))+' ('+str(int(''.join(segment[0:2]),16))+')')
    udpHeader.append(udpFields[1]+': 0x'+str(''.join(segment[2:4]))+' ('+str(int(''.join(segment[2:4]),16))+')')
    udpHeader.append(udpFields[2]+': 0x'+str(''.join(segment[4:8]))+' ('+str(int(''.join(segment[4:8]),16))+')')
    udpHeader.append(udpFields[3]+': 0x'+str(''.join(segment[8:12])))

    return udpHeader

def tcpHandler(segment):
    tcpHeader=['****** Transmission Control Protocol ******']
    ##Standard TCP Fields
    tcpHeader.append(tcpFields[0]+': 0x'+str(''.join(segment[0:2]))+' ('+str(int(''.join(segment[0:2]),16))+')')
    tcpHeader.append(tcpFields[1]+': 0x'+str(''.join(segment[2:4]))+' ('+str(int(''.join(segment[2:4]),16))+')')
    tcpHeader.append(tcpFields[2]+': 0x'+str(''.join(segment[4:8]))+' ('+str(int(''.join(segment[4:8]),16))+')')
    tcpHeader.append(tcpFields[3]+': 0x'+str(''.join(segment[8:12]))+' ('+str(int(''.join(segment[8:12]),16))+')')

    bitWise=bin(int(''.join(segment[12:13]),16))[2:].zfill(8)+bin(int(''.join(segment[13:14]),16))[2:].zfill(8)
    tcpHeader.append(tcpFields[4]+': '+hex(int(''.join(bitWise[:4]),2))+'('+str(int(32*int(''.join(bitWise[:4]),2)/8))+' bytes)')
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
    tcpHeader.append(['Options:'])
    count=20
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
    return tcpHeader

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
    hexStr = f.read().split()
    f.close()

    segment=hexStr
    '''
    print('Transmission Control Protocol')
    tcpHeader = tcpHandler(segment)
    print_list(tcpHeader,0)
    '''
    header = httpHandler(segment)
    print(header[0])
    print_list(header[1:],0)

if __name__ == "__main__":
    main()