# Multiprocess Offline Network Protocol Analyzer

This project implements a multiprocess offline network protocol analyzer, a tool used to analyze signals and data traffic over a communication channel. For this project purpose, the analyzer can only process the following list of protocols:

* Layer 2: Ethernet
* Layer 3: IP(IPv4, IPv6)
* Layer 4: TCP, UDP
* Layer 7: HTTP (header only of requests and replies).

The result will be shown on the terminal and be saved as a result.txt file in the current folder. 


## Design and Implementation

The program, in a high-level sense, consists of two parts: trace pretreatment and trace interpreter. In the trace pretreatment, the program will read a hex dumb of multiples Ethernet traces (without preamble and FCS fields), divide them into separate frames (if there are more than one frame), and then discern leading offsets, comments/text dumps, and frames. Then, all frames will be passed to the trace interpreter where each frame will be disassembled and be handled by layer analyzers. When there is more than one frame, the interpreter will create a process pool, and each process will interpret each frame. Once one process is done, a lock will lock IO (print) until the printing is finished. 

* Ethernet Layer Handler: It will analysis and return the standard Ethernet header.
```python
def EthernetHandler(frame):
    ...
    if(protocol==2048): #IPv4
        EthernetHeader.append(EthernetFields[2]+': 0x'+str(''.join(frame[12:14]))+' (IPv4)')
    else:               #IPv6
        EthernetHeader.append(EthernetFields[2]+': 0x'+str(''.join(frame[12:14]))+' (IPv6)')
    return EthernetHeader
```
* IP Layer Handler: In the beginning, the handler will determine if it is IPv4 or IPv6. Then, it will pass the packet to different IP versions handler. 
```python
def IPHandler(packet):
    if(int(packet[0],16)>>4==4):
        return IPv4Handler(packet)
    else:
        return IPv6Handler(packet)
```

In both handlers, the IP header and the transport protocol will be returned and are used to print the result and to let the next handler know which transport protocol it is going to be, respectively. Notice that though IPv6 Handler is given, it is not actually implemented. In the IPv4 handler, it can only process either no option or record route (RR) option. 

* Transport Layer Handler: The argument, protocol, is comming from the IP Handler. Since there are only two (TCP and UDP) are implemented, the handler will call UDP handler if the protocol is 17. Otherwise, it should go to a TCP handler.  
```python
def transportHandler(segment,protocol):
    if(protocol==17):
        return udpHandler(segment)
    else:
        return tcpHandler(segment)
```

In both handlers, the content of the header and the length of the header is returned. The latter is used to determine if there is an application layer that follows up.

* Application Layer Handler: HTTP is the only application protocol implemented, so the handler will read each line and store the keywords in the header. Once it reads two consecutive \n, it will cut off here, compute the data in the rest, and return the header. 
```python
def httpHandler(data):
    ...
        ...
        if(data[i]=='0d' and data[i+1]=='0a' and data[i+2]=='0d' and data[i+3]=='0a'):
            httpHeader.append('File Data: '+str(len(data)-i-4)+' bytes')
            return httpHeader
    return httpHeader
```

## Input
The input to the program is a text file containing the hex dumb of multiples Ethernet frames (without preamble and FCS fields):

* Each byte is encoded as two hex characters.  
* Each byte is surrounded by a space. 
* Each line begins with an offset encoded on at least 1 byte (2 hex characters) describing the position of the first byte on the line in the frame.
* Each new frame starts with an offset of 0 and there is a space separating the offset from the following bytes. 
* The offset is a hex number of at least two hex characters. 
* All hex characters can be uppercase or lowercase.
* There is no limit on the length or the number of bytes per line.
* Any text dump at the end of the line should be ignored. Any hex numbers in this text should also be ignored.
* Lines of text between the bytestring lines should be ignored. 
* Any line without a leading offset should be ignored. 
* Any incomplete line should raise an error message specifying the corrupted line. 

### Sample Input
<img width="523" alt="Screen Shot 2020-07-31 at 10 22 02 AM" src="https://user-images.githubusercontent.com/34410439/88993684-2fee2200-d319-11ea-94e2-b37c4e2306a8.png">

### Sample Output
<img width="523" alt="Screen Shot 2020-07-31 at 10 22 03 AM" src="https://user-images.githubusercontent.com/34410439/88993172-c588b200-d317-11ea-8d26-7ddfe0a07364.png">

## How to

To see the sample case, run 
```
make sample
```
which is a multiple traces including UDP, TCP, and HTTP. 

There are other seperate test cases such as ```make tcp``` and ```make http```. ```make clean``` is used to clean the result.txt.

To choose a given file, do
```
make all
```
