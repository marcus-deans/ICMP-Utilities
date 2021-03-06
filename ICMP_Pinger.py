import socket
from socket import *
import os
import sys
import struct
import time
import select

ICMP_ECHO_REQUEST = 8


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rtt_count, rtt_sum, rtt_min, rtt_max
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."
        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        # Fetch the ICMP header from the IP packet
        icmpHeader = recPacket[20:28]

        # Go through the header and retrieve the characterizing values that we will examine
        icmpType, icmpCode, myChecksum, packetID, mySequence = struct.unpack('bbHHh', icmpHeader)

        # If the ICMP Type is erroneous, that is, anything but 0 for echo ping response, print error message
        if icmpType != 0:
            if icmpCode == 0:  # ICMP Type 0 and Code 0 case is unreachable destination network
                return "Destination Network Unreachable"
            if icmpCode == 1:  # ICMP Type 0 and Code 2 case is unreachable destination host
                return "Destination Host Unreachable"
            if icmpCode == 2:  # ICMP Type 0 and Code 3 case is unreachable destination protocol
                return "Destination Protocol Unreachable"
            return "Other Error: Expected ICMP Type = 0 and Code = 0, but obtained {} and {}".format(icmpType,
                                                                                                  icmpCode)
            # Any other ICMP Code with Type not 0 fits into 'other errors' category

        if packetID != ID:  # if the packet ID is not as expected, display error
            return 'Expected Packet ID = {}, but obtained {}'.format(ID, packetID)

        bytesAsDouble = struct.calcsize("d")  # calculate the size of a byte
        # obtain the time that the packet was sent, by retrieving from struct
        timeSent = struct.unpack("d", recPacket[28:28 + bytesAsDouble])[0]

        rtt = (timeReceived - timeSent) * 1000  # RTT is arrival - departure, scaled up
        rtt_count += 1  # Increment number of packets thus far (for average)
        rtt_sum += rtt  # Increment sum of RTT thus far (for average)
        rtt_min = min(rtt, rtt_min)  # Compute the new minimum RTT
        rtt_max = max(rtt, rtt_max)  # Compute the new maximum RTT

        ipHeader = struct.unpack('!BBHHHBBH4s4s', recPacket[:20])  # retrieve IP header from struct
        ttl = ipHeader[5]  # TTL is at appropriate field within IP Header
        sendAddress = inet_ntoa(ipHeader[8])  # Determine the IP address via conversion of field in IP header
        packetLength = len(recPacket) - 20  # Determine the packet length by subtracting header length

        # Explain each line

        # Fill in end
        timeLeft = timeLeft - howLongInSelect # identify new time left having waited for response
        if timeLeft <= 0: # if remaining time is less than 0, packet timed out so display
            return "Request timed out."

        # return results of ping packet receipt, including most of the fields identified above from struct
        return 'Received {} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms'.format(packetLength, sendAddress,
                                                                                     mySequence, ttl, rtt)


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0

    # Make a dummy header with a 0 checksum

    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    try:
	mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str
    except:
    	print("Destination Network Unreachable")
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details: http://sock- raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=1):
    global rtt_count, rtt_sum, rtt_min, rtt_max
    rtt_count = 0
    rtt_sum = 0
    rtt_min = float('+inf')
    rtt_max = float('-inf')
    count = 0
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    # dest = "128.119.8.148"

    print("Pinging " + dest + " using Python:")
    print("")
    # Send ping requests to a server separated by approximately one second
    try:
        while True:
            count += 1
            delay = doOnePing(dest, timeout)
            print(delay)
            time.sleep(1)  # one second return delay
    except KeyboardInterrupt:
        if count != 0:
            print("_____ Ping Statistics Gathered for {} _____".format(host))
            packetLossPercentage = 100.0 - rtt_count * 100.0 / count
            print('{} packets transmitted, {} packets received, {:.1f}% packet loss'.format(count, rtt_count,
                                                                                            packetLossPercentage))
            if rtt_count != 0:
                print('RTT Min: {:.3f}ms | RTT Avg: {:.3f}ms | RTT Max: {:.3f}ms'.format(rtt_min, rtt_sum / rtt_count,
                                                                                         rtt_max))


# ping("127.0.0.1")
# ping("umass.edu")
# ping("alibaba.com")
# ping("bbc.com")
# ping("unimelb.edu.au")
ping("pretoriazoo.org")
# ping("128.119.8.148")
