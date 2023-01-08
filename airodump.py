# -*- coding: utf-8 -*-
"""
Created on Thu Jan  5 17:30:21 2023

@author: kimse

BSSID, Beacons=?, (#Data=?), (ENC=?), ESSID, (PWR=atenna signal) 
"""


import socket, sys, os

PACKET_INFO = []


def analyzer_80211(pkt, ch, interface_name):
    flag = 0
    CLR = "\x1B[0K"
    
    packetInfo = packet802()
    packetInfo.setInfomember(pkt)
    temp = [packetInfo.BSSID, packetInfo.Beacons, packetInfo.Data, 
            packetInfo.ESSID, packetInfo.PWR, packetInfo.ENC, ch]
        
    
    if(packetInfo.Type == b'\x80'):
        for i in PACKET_INFO:
            if(packetInfo.BSSID == i[0]):
                i[1] += 1
                i[4] = packetInfo.PWR
                flag = 1
                break
            
        if(flag == 0):
            PACKET_INFO.append(temp)
            #PACKET_INFO.sort(key=lambda x:x[5])
            os.system("clear")
             
            print("interface Name : {}{}".format(interface_name, CLR))
            print("{:<22}{:<11}{:<9}{:<22}{:<9}{:<10}{:<9}{}"
                  .format("BSSID", "Beacons", "#Data", "ESSID", "PWR", "ENC", "CH",CLR))
            
            for i in PACKET_INFO:
                if(i[3] == ''):
                    print("{:<22}{:<11}{:<9}{:<22}{:<9}{:<17}{:<9}{}"
                          .format(i[0], i[1], i[2], '????', i[4], i[5], i[6], CLR))
                
                else:
                    print("{:<22}{:<11}{:<9}{:<22}{:<9}{:<17}{:<9}{}"
                          .format(i[0], i[1], i[2], i[3], i[4], i[5], i[6], CLR))
            
        
        
    elif(packetInfo.Type == b'\x88'):
        for i in PACKET_INFO:
            if(packetInfo.BSSID == i[0]):
                i[2] += 1
                i[4] = packetInfo.PWR
                break

    
    else:
        return
    
    
def printInterface(interface_name):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((interface_name,0x0003))
    
    try:
        while True:    
            for channel in range(1, 13):
                os.system("iwconfig " + interface_name + " channel " + str(channel))
                packet = s.recvfrom(2048)[0]
                analyzer_80211(packet, channel, interface_name)
    
    except KeyboardInterrupt:
        s.close()
        exit(0)
            
class packet802():
    headerSize = 0
    Type = 0
    BSSID = ""
    Beacons = 0
    Data = 0
    ESSID = ""
    PWR = 0
    
    def __init__(self): 
        self.BSSID = ""
        self.Beacons = 0
        self.Data = 0
        self.ESSID = ""
        self.PWR = 0
        self.ENC = ""
       
    def setInfomember(self, pkt): 
        self.headerSize = int.from_bytes(pkt[2:4], byteorder='little', signed=True)
        self.Type = pkt[self.headerSize:self.headerSize+1]
        self.PWR = int.from_bytes(pkt[18:19], byteorder='big', signed=True)
        
        if(self.Type == b'\x80'): #beacon
            self.BSSID = pkt[40:46].hex(":")
            self.ESSID = bytearray.fromhex(pkt[62:62+ int(pkt[61:62].hex(), 16)].hex()).decode()
            
            index = 62 + int(pkt[61:62].hex(), 16)
            size = 0
            try:
                while(True):
                    if(pkt[index:index+1] == b''):
                        self.ENC = "OPT"
                        break
                    
                    
                    elif(pkt[index:index+1] == b'\x30'): #RSN tag
                        if(pkt[index+7:index+8] == b'\x01'):
                            self.ENC = "WEP"
                        
                        elif(pkt[index+7:index+8] == b'\x02'):
                            self.ENC = "WPA - TKIP"
                                                     
                        elif(pkt[index+7:index+8] == b'\x03'):
                            self.ENC = "WRAP"
                        
                        elif(pkt[index+7:index+8] == b'\x04'):
                            self.ENC = "WPA2 - CCMP"
                        
                        elif(pkt[index+7:index+8] == b'\x05'):
                            self.ENC = "WEP104"
                        
                        elif(pkt[index+7:index+8] == b'\x09'):
                            self.ENC = "WPA2 - GCMP"
                        
                        elif(pkt[index+7:index+8] == b'\x0c'):
                            self.ENC = "WPA2 - GMAC"
                        
                        else:
                            self.ENC = "????"
                        
                        break
                    
                    
                    else:
                        index += 1
                        size = int.from_bytes(pkt[index:index+1], byteorder='little', signed=True)
                        index += size + 1
                    
            except:
                self.ENC = "????"
            
            
        elif(self.Type == b'\x88'): #Qos data
            self.BSSID = pkt[31:37].hex(":")




printInterface(sys.argv[1])

