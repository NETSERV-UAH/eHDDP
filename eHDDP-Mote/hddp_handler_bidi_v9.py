''' 
 * This file is part of the HDDP Switch distribution (https://github.com/gistnetserv-uah/eHDDP).
 * Copyright (c) 2020.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 '''

#!/usr/bin/python

import socket, struct, os, array, uuid, time, sys
from scapy.all import *
import numpy as np
import select, random
from datetime import datetime

ETH_HDDP = 65450 #valor del eth de hddp
WIFI_ID_NUM = 1
INPORT = 1
OUTPORT = 2
NUM_DEVICES = 31
HDDP_NEW = 0
HDDP_REQ = 1
HDDP_REP = 2
HDDP_ACK = 3
HDDP_RESEND = 4
TIMER_WITH_PKT = 300
TIMER_WITHOUT_PKT = 3000
NODE_NO_SDN = 2 #id del dispositivo switch no sdn
LOG_ACTIVO = True
NUM_RESEND = 0
SIZE_MAC = 6
SIZE_TYPE_DEV = 2
SIZE_ID_MAC = 8
SIZE_PORT = 4


 
class hddp_sniffer:

        #eth_header = {"mac_src" : [], "mac_dst" : [], "eth_type" : 0}
        #eth_hddp = {"mac_sig": [], "OpCode": 0, "Num_hops": 0, "Time_Block": 0, "Num_Sec": 0, "links": []}
        #ID_Propia = 0 # es la mac pasada a unint64

        def __init__(self):
                self.num_veces_repetido = 0
                self.last_timer = 0
                self.timeout = TIMER_WITHOUT_PKT
                self.resend_time = 300 #(ms)
                self.Id_onos = -1
                self.mac_myself = []
                self.interface_name = []
                self.ID_Propia = []
                self.block_table = {"mac_src": [], "mac_ant":[], "timestamp": 0, "Num_Sec": 0, "interfaz_salida":""}
                #realizar select segun tarjetas
                self.inputs = []
                self.outputs = []
                self.message_queues = {}
                self.request_waiting_ack = {}
                self.request_waiting_reply = {}
                self.request_resent = {}
                self.reply_waiting_ack = {}
                self.reply_waiting_ack_counter = {}
                self.type_device = -1
                self.num_sec = 0
                self.num_packet_request_exit = int(0)
                self.num_packet_reply_ucast_exit = int(0)
                self.num_packet_reply_bcast_exit = int(0)
                self.num_packet_ack_exit = int(0)
                self.num_packet_request_ingress = int(0)
                self.num_packet_reply_ucast_ingress = int(0)
                self.num_packet_reply_bcast_ingress = int(0)
                self.num_packet_ack_ingress = int(0)
                self.num_packet_hddp_ingress = int(0)
                self.nombre_fichero = "datos.txt"
                self.nombre_log = "log.txt"
                self.log_activo = True
                self.nodo_mixto = False
                self.estado = int(0)
                self.distance_sdn = int(0)
                        
   
        def insert_interfaces(self, interface_name, mac_interface):
                new_int = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                new_int.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
                new_int.bind((interface_name, ETH_P_ALL))
                new_int.settimeout(0.0)

                #datos
                self.interface_name.append(interface_name)
                self.mac_myself.append(mac_interface)
                self.ID_Propia.append(self.mac_to_int(mac_interface))  
                if (self.Id_onos > self.mac_to_int(mac_interface) or self.Id_onos == -1):
                        self.Id_onos = self.mac_to_int(mac_interface)

                #insertamos en lista
                self.inputs.append(new_int)
        
        def insert_file_name(self, file_name):
                self.nombre_fichero = "~/"+str(file_name)
                self.nombre_log = "~/log-sta"+str(self.Id_onos)+".txt"
        
        def set_active_log(self, activar):
                self.log_activo = activar
        
        def insert_type_device(self, num_wlan, num_eth):
                #seleccionar el tipo de dispositivo depende de nuestras interfaces
                if (num_wlan == 0 or num_eth > 0):
                        #si no tenemos wlan o teniendo wlan tiene eth -> TYPE_DEVICE = 2 #indicamos que es switch no sdn
                        self.type_device = NODE_NO_SDN	
                        if (num_wlan == 0):
                                self.nodo_mixto = False;
                        else:
                                self.nodo_mixto = True
                else:
                        #si solo tiene wlan -> TYPE_DEVICE = [3, 15] -> puede ser cualquier sensor
                        self.nodo_mixto = False
                        self.type_device = int(random.randint(3, 15))


        def get_id_onos(self):
                return self.Id_onos;

        def mac_to_int(self, mac):
                #print "id: "+str (int(mac.translate(None, ":.- "), 16))
                return int(mac.translate(None, ":.- "), 16)
       
        def int_to_mac(self, macint):
                if type(macint) != int:
                        raise ValueError('invalid integer')
                return ':'.join(['{}{}'.format(a, b) for a, b in zip(*[iter('{:012x}'.format(macint))]*2)])

        def struc_to_mac(self, mac_struct):
                mac = ""
                for pos in range(0, 6):
                        if (len(mac_struct[pos]) < 2):
                                mac += "0"+str(mac_struct[pos])
                        else:
                                mac += str(mac_struct[pos])
                        if (pos < 5):
                                mac += ":"
                return mac

        def mac_interface(self, interfaz):
                try:
                        return self.mac_myself[self.inputs.index(interfaz)]
                except:
                        return -1;
       
        def id_interfaz(self, interfaz):
                try:
                        return self.ID_Propia[self.inputs.index(interfaz)]
                except:
                        return -1;
       
        def num_interfaz(self, interfaz):
                try:
                        return int(self.inputs.index(interfaz)+1)
                except:
                        return -1;

        def name_interfaz(self, interfaz):
                try:
                        return self.interface_name[self.inputs.index(interfaz)]
                except:
                        return -1;
       
        def pkt_for_me(self, mac, Num_Sec, pkt, hddp_fix_len, num_devices):
                try:
                        str_mac = self.struc_to_mac(mac)
                        if (str_mac == 'ff:ff:ff:ff:ff:ff'):
                            
                            configuration, types, ids_pkt, inports, outports = self.read_data_devices(pkt, hddp_fix_len, num_devices-1)
                            if (len(ids_pkt) <= 1):
                                return 1; 
                            if (ids_pkt[len(ids_pkt)-1] == self.Id_onos): 
                                return -1
                            elif ((ids_pkt.count(self.Id_onos) == 0) or 
                                (ids_pkt.count(self.Id_onos) < self.num_veces_repetido) or 
                                (self.block_table['Num_Sec'] >= Num_Sec) or 
                                ((ids_pkt.count(self.Id_onos) == self.num_veces_repetido) and ids_pkt[len(ids_pkt) - 2] == self.Id_onos)):
                                return 1;
                            else:
                                return -1;
                        for pos in range (0, len(self.mac_myself)):
                            if (str_mac == self.mac_myself[pos]):
                                return 1;
                        return -1;
                except:
                        return -1;


        def make_header_hppd_fixed(self, eth_header, hddp_header):
                
                eth_type = [hex(eth_header["eth_type"] >> i & 0xff) for i in (8,0)]
                Version = [hex(hddp_header["Version"] & 0xff)]
                Opcode = [hex(hddp_header["OpCode"] & 0xff)]
                Num_hops = [hex(hddp_header["Num_hops"] & 0xff)]
                Num_Sec = [hex(hddp_header["Num_Sec"] >> i & 0xff) for i in (56,48,40,32,24,16,8,0)]
                mac_size = [hex(hddp_header["mac_size"] & 0xff)]
                Num_Ack = [hex(int(hddp_header["Num_Ack"] >> i & 0xff)) for i in (56,48,40,32,24,16,8,0)]
                Time_Block = [hex(hddp_header["Time_Block"] >> i & 0xff) for i in (24,16,8,0)]

                pkt = struct.pack("!6B6B2B",
                        int(bytes(eth_header["mac_dst"][0]),16), int(bytes(eth_header["mac_dst"][1]),16), int(bytes(eth_header["mac_dst"][2]),16),
                        int(bytes(eth_header["mac_dst"][3]),16), int(bytes(eth_header["mac_dst"][4]),16), int(bytes(eth_header["mac_dst"][5]),16),
                        int(bytes(eth_header["mac_src"][0]),16), int(bytes(eth_header["mac_src"][1]),16), int(bytes(eth_header["mac_src"][2]),16),
                        int(bytes(eth_header["mac_src"][3]),16), int(bytes(eth_header["mac_src"][4]),16), int(bytes(eth_header["mac_src"][5]),16),
                        int(bytes(eth_type[0]),16), int(bytes(eth_type[1]),16));

                pkt += struct.pack("!1B1B1B8B1B",
                        int(bytes(Version[0]),16), int(bytes(Opcode[0]),16), int(bytes(Num_hops[0]),16),
                        int(bytes(Num_Sec[0]),16), int(bytes(Num_Sec[1]),16), int(bytes(Num_Sec[2]),16), int(bytes(Num_Sec[3]),16),
                        int(bytes(Num_Sec[4]),16), int(bytes(Num_Sec[5]),16), int(bytes(Num_Sec[6]),16), int(bytes(Num_Sec[7]),16),
                        int(bytes(mac_size[0]),16))

                pkt += struct.pack("!"+str(hex(hddp_header["mac_size"]))+"B8B"+str(hex(hddp_header["mac_size"]))+"B"+str(hex(hddp_header["mac_size"]))+"B4B",
                        int(bytes(hddp_header["mac_sig"][0]),16), int(bytes(hddp_header["mac_sig"][1]),16), int(bytes(hddp_header["mac_sig"][2]),16),
                        int(bytes(hddp_header["mac_sig"][3]),16), int(bytes(hddp_header["mac_sig"][4]),16), int(bytes(hddp_header["mac_sig"][5]),16),
                        int(bytes(Num_Ack[0]),16), int(bytes(Num_Ack[1]),16), int(bytes(Num_Ack[2]),16), int(bytes(Num_Ack[3]),16),
                        int(bytes(Num_Ack[4]),16), int(bytes(Num_Ack[5]),16), int(bytes(Num_Ack[6]),16), int(bytes(Num_Ack[7]),16),
                        int(bytes(hddp_header["last_mac"][0]),16), int(bytes(hddp_header["last_mac"][1]),16), int(bytes(hddp_header["last_mac"][2]),16),
                        int(bytes(hddp_header["last_mac"][3]),16), int(bytes(hddp_header["last_mac"][4]),16), int(bytes(hddp_header["last_mac"][5]),16),
                        int(bytes(hddp_header["src_mac"][0]),16), int(bytes(hddp_header["src_mac"][1]),16), int(bytes(hddp_header["src_mac"][2]),16),
                        int(bytes(hddp_header["src_mac"][3]),16), int(bytes(hddp_header["src_mac"][4]),16), int(bytes(hddp_header["src_mac"][5]),16),
                        int(bytes(Time_Block[0]),16), int(bytes(Time_Block[1]),16), int(bytes(Time_Block[2]),16), int(bytes(Time_Block[3]),16)
                );


                return pkt;    

        def select_type_read_buffer(self, len_to_read):
            if len_to_read == 8:
                return "Q"
            elif len_to_read == 4:
                return "L"
            elif len_to_read == 2:
                return "H"
            else:
                return "B"

        def read_data_devices (self, pkt, hddp_fix_len, num_datos):
            configuration = []
            types =[]
            id_devices = []
            inports = []
            outports = []
            size_type_dev = size_id_mac = size_port = int(0);

            for i in range(0, num_datos):
                configuration.append(int(struct.unpack("!B", 
                    pkt[int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i :
                        int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 ])[0]))
               
                size_type_dev = int((configuration[i] & 0b11000000) >> 6) + 1 
                size_id_mac = int((configuration[i] & 0b00111000) >> 3 ) + 1
                size_port = int((configuration[i] & 0b00000110) >> 1) + 1
                bidirectional = int(configuration[i] & 0b00000001)

                types.append(int(struct.unpack("!"+str(self.select_type_read_buffer(size_type_dev)), 
                    pkt[int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 : 
                        int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev])[0]))
                
                id_devices.append(int(struct.unpack("!"+str(self.select_type_read_buffer(size_id_mac)), 
                    pkt[int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev : 
                        int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac])[0]))
                
                inports.append(int(struct.unpack("!"+str(self.select_type_read_buffer(size_port)), 
                    pkt[int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac : 
                        int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac + size_port])[0]))
                
                print len(pkt[int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac + size_port : 
                              int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac + size_port + size_port])

                outports.append(int(struct.unpack("!"+str(self.select_type_read_buffer(size_port)), 
                    pkt[int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac + 1 * size_port :  
                        int(hddp_fix_len)+i*(size_type_dev + size_id_mac + 2 * size_port) + i + 1 + size_type_dev + size_id_mac + 2 * size_port])[0]))

            return configuration, types, id_devices, inports, outports

        def serialize_datas(self, data_devices, type_data):
                return struct.pack("!1"+str(type_data),data_devices)
                
        def read_all_data_packet(self, pkt, hddp_packet, eth_header, hddp_header, New_packet, num_ack, num_datos = NUM_DEVICES):
                position = 0
                if (New_packet == HDDP_NEW and num_ack == 0):
                        
                        config_myself = bin(int(SIZE_TYPE_DEV-1) << 6 | int(SIZE_ID_MAC-1) << 3 | int (SIZE_PORT -1) << 1 | int (1))
                        configurations = []
                        types = []
                        id_devices = []
                        inports = []
                        outports = []
                        position = 0

                elif (New_packet == HDDP_RESEND and num_ack != 0):
                        configurations = self.reply_waiting_ack[num_ack]["bidirectionals"][0:num_datos]
                        types = self.reply_waiting_ack[num_ack]["types"][0:num_datos]
                        id_devices = self.reply_waiting_ack[num_ack]["id_devices"][0:num_datos]
                        inports = self.reply_waiting_ack[num_ack]["inports"][0:num_datos]
                        outports = self.reply_waiting_ack[num_ack]["outports"][0:num_datos]
                        position = num_datos - 1 

                else:
                        configurations, types, id_devices, inports, outports = self.read_data_devices(pkt, len(hddp_packet), num_datos)
                        position = num_datos - 1 
                
                return types, id_devices, inports, outports, configurations, position
                

        def create_hddp_packet(self, pkt, eth_header, hddp_header, New_packet, entry_interface, out_interface, link_bidi, num_ack = 0):
                
                hddp_header["last_mac"] = str(self.mac_interface(out_interface)).split(":") 
                eth_header["mac_src"] = str(self.mac_interface(out_interface)).split(":"); 

                hddp_packet = self.make_header_hppd_fixed(eth_header, hddp_header)
                types, id_devices, inports, outports, configurations, position = self.read_all_data_packet( 
                        pkt, hddp_packet, eth_header, hddp_header, New_packet, num_ack, hddp_header['Num_hops'] - 1 )

                
                types.append(self.type_device)
                id_devices.append(self.Id_onos) 
                inports.append(self.num_interfaz(entry_interface))
                outports.append(self.num_interfaz(out_interface))
                config_myself = bin(int(SIZE_TYPE_DEV-1) << 6 | int(SIZE_ID_MAC-1) << 3 | int (SIZE_PORT -1) << 1 | int (link_bidi))
                configurations.append(int(config_myself,2)) 

                for i in range (0, hddp_header['Num_hops']):
                    hddp_packet +=  self.serialize_datas(configurations[i],"B") 
                    
                    size_type_dev = int((configurations[i] & 0b11000000) >> 6) + 1 
                    size_id_mac = int((configurations[i] & 0b00111000) >> 3 ) + 1
                    size_port = int((configurations[i] & 0b00000110) >> 1) + 1

                    hddp_packet +=  self.serialize_datas(types[i],self.select_type_read_buffer(size_type_dev))
                    hddp_packet +=  self.serialize_datas(id_devices[i],self.select_type_read_buffer(size_id_mac))
                    hddp_packet +=  self.serialize_datas(inports[i],self.select_type_read_buffer(size_port))
                    hddp_packet +=  self.serialize_datas(outports[i],self.select_type_read_buffer(size_port))
                
                return hddp_packet, types, id_devices, inports, outports, configurations
        
        def save_packet_waiting_ack(self, pkt, eth_header, hddp_header, entry_interface):
                hddp_packet = self.make_header_hppd_fixed(eth_header, hddp_header)
                types, id_devices, inports, outports, bidirectionals, position = self.read_all_data_packet(pkt, 
                        hddp_packet, eth_header, hddp_header, HDDP_REP, 0, hddp_header['Num_hops'] - 1 )

                id_devices_request = id_devices[position]
                types_request = types[position]              
                outports_request = outports[position]
                inports_request = outports_request

                if (id_devices_request == 0):
                        return;

                self.estado += int(1)

                self.reply_waiting_ack[hddp_header["Num_Ack"]] = {}
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["eth_header"] = eth_header
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"] = hddp_header
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"]["Num_hops"] = 2
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["types"] = [0] * self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"]["Num_hops"]
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["types"][0] = types_request
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["id_devices"] = [0] * self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"]["Num_hops"]
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["id_devices"][0] = id_devices_request
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["inports"] = [0] * self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"]["Num_hops"]
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["inports"][0] = inports_request
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["outports"] = [0] * self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"]["Num_hops"]
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["outports"][0] = outports_request
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["bidirectionals"] = [0] * self.reply_waiting_ack[hddp_header["Num_Ack"]]["hddp_header"]["Num_hops"]
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["bidirectionals"][0] = 1
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["time_send"] = time.time()*1000
                self.reply_waiting_ack[hddp_header["Num_Ack"]]["entry_interface"] = entry_interface

                
                self.timeout = TIMER_WITH_PKT

        def remove_resend_request_by_reply(self, hddp_header):
            if NUM_RESEND > 0 and len(self.request_waiting_reply) > 0:
                if ((self.request_waiting_reply.has_key(hddp_header["Num_Sec"])) and 
                    (self.block_table["Num_Sec"] > hddp_header["Num_Sec"] or self.block_table["mac_ant"] != hddp_header["last_mac"])):
                        self.request_waiting_reply.pop(hddp_header["Num_Sec"], None)
                        if (self.request_resent.has_key(hddp_header["Num_Sec"])):
                            self.request_resent.pop(hddp_header["Num_Sec"], None)
                        
                        if len(self.reply_waiting_ack) == 0 and len(self.request_waiting_reply) == 0:
                            
                            self.timeout = TIMER_WITHOUT_PKT
            return

        def clean_pkt_to_resend(self, hddp_header):
            if NUM_RESEND > 0 and len(self.request_waiting_reply) > 0:
                
                keys_request_waiting_reply = self.request_waiting_reply.keys() 
                for num_sequece_resend_request in keys_request_waiting_reply:
                    if (num_sequece_resend_request < int(hddp_header["Num_Sec"])):
                        try:
                            self.request_waiting_reply.pop(num_sequece_resend_request, None)
                            self.request_resent.pop(num_sequece_resend_request, None)
                        except Exception as exception:
                            continue

                keys_reply_waiting_ack = self.reply_waiting_ack.keys()
                for resend_reply in keys_reply_waiting_ack:
                    if int(self.reply_waiting_ack[resend_reply]["time_send"]/1000) < int(hddp_header["Num_Sec"]):
                        self.reply_waiting_ack.pop(resend_reply, None);
                
                
                if len(self.reply_waiting_ack) == 0 and len(self.request_waiting_reply) == 0:
                    self.timeout = TIMER_WITHOUT_PKT
            return

        def save_request_to_resend(self, timer, hddp_header, interface, hddp_packet_request, tipo):
            if (NUM_RESEND > 0): 
                
                self.estado += int(1)                        
                if not self.request_waiting_reply.has_key(hddp_header["Num_Sec"]):
                    self.request_waiting_reply[hddp_header["Num_Sec"]]= {}
                if not self.request_waiting_reply[hddp_header["Num_Sec"]].has_key(timer):
                    self.request_waiting_reply[hddp_header["Num_Sec"]][timer] = {}
                if not self.request_waiting_reply[hddp_header["Num_Sec"]][timer].has_key(interface):
                    self.request_waiting_reply[hddp_header["Num_Sec"]][timer][interface] = hddp_packet_request
                    self.request_resent[hddp_header["Num_Sec"]] = 0
                    self.timeout = TIMER_WITH_PKT
            return
       
        def process_hddp_request_wifi(self, pkt, eth_header, hddp_header, entry_interface):
                mac_ant = hddp_header["mac_sig"];
                mac_src = eth_header["mac_src"];

                self.clean_pkt_to_resend(hddp_header);
                
                if (int(hddp_header["Num_Sec"]) < self.block_table['Num_Sec']):
                        return;

                
                if (int(hddp_header["Num_Sec"]) > self.block_table['Num_Sec']):
                        
                        if (self.distance_sdn == 0 or self.distance_sdn < hddp_header["Num_hops"]):
                                self.distance_sdn = hddp_header["Num_hops"];
                        
                        self.estado += int(1)
                       
                        hddp_header["last_mac"] = str(self.mac_myself[0]).split(":") 
                        hddp_header["Num_hops"] = int(hddp_header["Num_hops"]) + 1      
                        for interface in self.inputs:
                                eth_header["mac_src"] = str(self.mac_interface(interface)).split(":"); 
                                hddp_header["mac_sig"] = eth_header["mac_src"];
                                hddp_packet_request, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(pkt, eth_header, 
                                        hddp_header, HDDP_REQ, entry_interface, interface, 1, 0)
                                if not self.message_queues.has_key(interface):
                                        self.message_queues[interface] = []
                                if not self.request_waiting_ack.has_key(hddp_header["Num_Sec"]):
                                        self.request_waiting_ack[hddp_header["Num_Sec"]]= {}
                                if not self.request_waiting_ack[hddp_header["Num_Sec"]].has_key(interface):
                                        self.request_waiting_ack[hddp_header["Num_Sec"]][interface] = {}
                                self.request_waiting_ack[hddp_header["Num_Sec"]][interface][time.time()*1000] = hddp_packet_request

                eth_header["mac_dst"] = mac_src;
                hddp_header["OpCode"] = HDDP_REP;
                hddp_header["mac_sig"] = mac_ant;
                hddp_header["src_mac"] = str(self.mac_interface(entry_interface)).split(":")
                hddp_header["Num_Ack"] = int(random.getrandbits(64));

                self.save_packet_waiting_ack(pkt, eth_header.copy(), hddp_header.copy(), entry_interface)

                
                hddp_header["Num_hops"] = int(1);
                
                link_bidi = 1
                hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
                        pkt, eth_header, hddp_header, HDDP_NEW, entry_interface, entry_interface, link_bidi, 0)

                if not self.message_queues.has_key(entry_interface):
                        self.message_queues[entry_interface] = []
                self.message_queues[entry_interface].append(hddp_packet_reply)
                if not entry_interface in self.outputs:
                        self.outputs.append(entry_interface)
                
                self.num_packet_reply_ucast_exit += int(1)

        def process_hddp_request_eth(self, pkt, eth_header, hddp_header, entry_interface):
                send_reply_block = 0
                mac_ant = hddp_header["mac_sig"];
                mac_src = eth_header["mac_src"];
                
                if (int(hddp_header["Num_Sec"]) < self.block_table['Num_Sec']):
                        return;

                if (int(hddp_header["Num_Sec"]) > self.block_table['Num_Sec']):
                        
                        send_reply_block = 0
                        self.block_table["mac_src"] = hddp_header["src_mac"]
                        self.block_table["mac_ant"] = hddp_header["last_mac"]; 
                        self.block_table["timestamp"] = (time.time() * 1000) + float(hddp_header["Time_Block"])
                        self.block_table["Num_Sec"] = int(hddp_header["Num_Sec"])
                        self.block_table["interfaz_salida"] = entry_interface 

                        
                        hddp_header["last_mac"] = str(self.mac_myself[0]).split(":") 
                        hddp_header["Num_hops"] = int(hddp_header["Num_hops"]) + 1 
                        timer = time.time() * 1000 
                        if  len(self.inputs) > 1 :
                            for interface in self.inputs:
                                if (interface != entry_interface):
                                    if (self.name_interfaz(interface).find("wlan") != -1 ):
                                            eth_header["mac_src"] = str(self.mac_interface(interface)).split(":"); 
                                    hddp_header["mac_sig"] = eth_header["mac_src"];
                                    hddp_packet_request, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(pkt, eth_header, 
                                            hddp_header, HDDP_REQ, entry_interface, interface, 1, 0)

                                    self.save_request_to_resend(timer, hddp_header, interface, hddp_packet_request, "ETH")

                                    if not self.message_queues.has_key(interface):
                                            self.message_queues[interface] = []
                                    self.message_queues[interface].append(hddp_packet_request)
                                    
                                    if not entry_interface in self.outputs:
                                            self.outputs.append(interface)
                                    self.num_packet_request_exit += int(1)
                                    
                else:
                        send_reply_block = 1

                if (send_reply_block == 1 or len(self.inputs) == 1 or self.nodo_mixto == True):                       
                        eth_header["mac_dst"] = mac_src;
                        hddp_header["OpCode"] = HDDP_REP;
                        hddp_header["mac_sig"] = mac_src;
                        hddp_header["src_mac"] = str(self.mac_interface(entry_interface)).split(":")
                        hddp_header["Num_Ack"] = int(random.getrandbits(64));

                        hddp_header["Num_hops"] = int(1);
                        link_bidi = 1
                        hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
                                pkt, eth_header, hddp_header, HDDP_NEW, entry_interface, entry_interface, link_bidi, 0)

                        self.num_packet_reply_ucast_exit += int(1)
                        if not self.message_queues.has_key(entry_interface):
                                self.message_queues[entry_interface] = []
                        self.message_queues[entry_interface].append(hddp_packet_reply)
                        if not entry_interface in self.outputs:
                                self.outputs.append(entry_interface)


        def process_hddp_reply(self, pkt, eth_header, hddp_header, entry_interface):
                self.remove_resend_request_by_reply(hddp_header)
                
                if (self.block_table["Num_Sec"] > hddp_header["Num_Sec"]):
                        return;

                next_mac = [str(hddp_header["mac_sig"][x].split('0x')[1]) for x in range(0, len(hddp_header["mac_sig"]))]
                if ( self.pkt_for_me(next_mac, hddp_header["Num_Sec"], pkt, len(self.make_header_hppd_fixed(eth_header, hddp_header)), hddp_header["Num_hops"]) < 0 ):
                        return
                else:
                        if int(hddp_header["Num_hops"]) == int(1) and self.name_interfaz(entry_interface).find("wlan") != -1 : 
                            hddp_header["OpCode"] = HDDP_ACK;

                            hddp_header["mac_sig"] = eth_header["mac_src"];
                            hddp_header["last_mac"] = str(self.mac_interface(entry_interface)).split(":")
                            eth_header["mac_dst"] = eth_header["mac_src"];
                            eth_header["mac_src"] = str(self.mac_interface(entry_interface)).split(":");
                            
                            hddp_packet_ack, types, id_devices, inports, outports, bidirectionals= self.create_hddp_packet(
                                    pkt, eth_header, hddp_header, HDDP_NEW, entry_interface, entry_interface, 1, 0)
                            if not self.message_queues.has_key(entry_interface):
                                    self.message_queues[entry_interface] = []
                            self.message_queues[entry_interface].append(hddp_packet_ack)
                            if not entry_interface in self.outputs:
                                    self.outputs.append(entry_interface)
                            self.num_packet_ack_exit += int(1)


                        hddp_header["OpCode"] = HDDP_REP;
                        hddp_header["Num_hops"] += int(1);
                        hddp_header["Num_Ack"] = int(random.getrandbits(64));

                        if (self.block_table["interfaz_salida"]):
                            eth_header["mac_dst"] = self.block_table["mac_ant"];
                            hddp_header["mac_sig"] = self.block_table["mac_ant"]; 
                            link_bidi = 1
                            hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
                                    pkt, eth_header, hddp_header, HDDP_REP, entry_interface, self.block_table["interfaz_salida"], link_bidi)
                            if not self.message_queues.has_key(self.block_table["interfaz_salida"]):
                                    self.message_queues[self.block_table["interfaz_salida"]] = []
                            self.message_queues[self.block_table["interfaz_salida"]].append(hddp_packet_reply)
                            if not self.block_table["interfaz_salida"] in self.outputs:
                                    self.outputs.append(self.block_table["interfaz_salida"])
                            self.num_packet_reply_ucast_exit += int(1)                       
                        else:
                            hddp_header["mac_sig"] = ['0xff','0xff','0xff','0xff','0xff','0xff']
                            eth_header["mac_dst"] = ['0xff','0xff','0xff','0xff','0xff','0xff']
                            link_bidi = 0
                            for interface in self.inputs:
                                hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
                                    pkt, eth_header, hddp_header, HDDP_REP, entry_interface, interface, link_bidi,0)
                                if not self.message_queues.has_key(interface):
                                    self.message_queues[interface] = []
                                self.message_queues[interface].append(hddp_packet_reply)
                                
                                if not interface in self.outputs:
                                    self.outputs.append(interface)
                                self.num_packet_reply_bcast_exit += int(1)
                return;
                                        
                        
        def process_hddp_ack_req(self, pkt, eth_header, hddp_header, entry_interface):
                self.process_hddp_ack_rep(pkt, eth_header, hddp_header)
                if (int(hddp_header["Num_Sec"]) != self.block_table['Num_Sec']):
                    self.block_table["mac_src"] = hddp_header["src_mac"]
                    self.block_table["mac_ant"] = hddp_header["last_mac"];
                    self.block_table["timestamp"] = (time.time() * 1000) + float(hddp_header["Time_Block"])
                    self.block_table["Num_Sec"] = int(hddp_header["Num_Sec"])
                    self.block_table["interfaz_salida"] = entry_interface 
                    self.process_send_hddp_req(pkt, eth_header, hddp_header);
                        
        def process_send_hddp_req(self, pkt, eth_header, hddp_header):
            if (self.request_waiting_ack.has_key(hddp_header["Num_Sec"])):
                timer = time.time() * 1000
                for interfaz_out in self.request_waiting_ack[hddp_header["Num_Sec"]].keys():
                    self.save_request_to_resend(timer, hddp_header, interfaz_out, self.request_waiting_ack[hddp_header["Num_Sec"]][interfaz_out].values()[0], "WIFI")

                    if not self.message_queues.has_key(interfaz_out):
                            self.message_queues[interfaz_out] = []
                    
                    self.message_queues[interfaz_out].append(
                            self.request_waiting_ack[hddp_header["Num_Sec"]][interfaz_out].values()[0])

                    if not interfaz_out in self.outputs:
                            self.outputs.append(interfaz_out)
                    
                    self.request_waiting_ack[hddp_header["Num_Sec"]].pop(interfaz_out, None)

                    self.num_packet_request_exit += int(1)
                
                self.request_waiting_ack.pop(hddp_header["Num_Sec"], None)


        def process_hddp_ack_rep(self, pkt, eth_header, hddp_header):
                if (self.reply_waiting_ack.has_key(hddp_header['Num_Ack'])):
                        self.reply_waiting_ack.pop(hddp_header["Num_Ack"], None);

        def process_hddp_frame(self,pkt, eth_header, hddp_header_data, entry_interface):
                hddp_header = {}

                command = "!1B1B1BQ1B"
                fields_fixed_hddp = struct.unpack(command, hddp_header_data[0:12])
                hddp_header["Version"] = int(fields_fixed_hddp[0])
                hddp_header["OpCode"] = int(fields_fixed_hddp[1])
                hddp_header["Num_hops"] = int(fields_fixed_hddp[2])
                hddp_header["Num_Sec"] = int(fields_fixed_hddp[3])
                hddp_header["mac_size"] = int(fields_fixed_hddp[4])

                command  = "!"+str(hddp_header["mac_size"])+"BQ"+str(hddp_header["mac_size"])+"B"+ str(hddp_header["mac_size"])+"BL"
                fields_max_fixed_hddp = struct.unpack(command, hddp_header_data[12:42]);
                hddp_header["mac_sig"] = [hex(int(fields_max_fixed_hddp[x])) for x in range(0,hddp_header["mac_size"])]
                hddp_header["Num_Ack"] = int(fields_max_fixed_hddp[hddp_header["mac_size"]])
                hddp_header["last_mac"] = [hex(int(fields_max_fixed_hddp[x])) for x in range(1+hddp_header["mac_size"],1+2*hddp_header["mac_size"])]
                hddp_header["src_mac"] = [hex(int(fields_max_fixed_hddp[x])) for x in range(1+2*hddp_header["mac_size"],1+3*hddp_header["mac_size"])]
                hddp_header["Time_Block"] = int(fields_max_fixed_hddp[1+3*hddp_header["mac_size"]])
                
                if (hddp_header["Num_Sec"] == self.num_sec and self.num_sec != 0):
                        self.last_timer = int(round(time.time() * 1000))
                
                if (hddp_header["Num_Sec"] > self.num_sec and self.num_sec != 0):
                        self.write_data_file();
                        
                if (self.num_sec == 0):
                        self.num_sec = hddp_header["Num_Sec"]

                self.num_packet_hddp_ingress += int(1)

                if(hddp_header["OpCode"] == HDDP_REQ):
                        self.num_packet_request_ingress += int(1)
                        if (self.name_interfaz(entry_interface) == -1):
                                return
                        if (self.name_interfaz(entry_interface).find("wlan") != -1 ):
                                self.process_hddp_request_wifi(pkt, eth_header, hddp_header, entry_interface)
                        else:
                                self.process_hddp_request_eth(pkt, eth_header, hddp_header, entry_interface)
                elif (hddp_header["OpCode"] == HDDP_REP): 
                        str_mac = self.struc_to_mac(hddp_header["mac_sig"])
                        if (str_mac == 'ff:ff:ff:ff:ff:ff' or str_mac == "0xff:0xff:0xff:0xff:0xff:0xff"):
                                self.num_packet_reply_bcast_ingress += int(1)
                        else:
                                self.num_packet_reply_ucast_ingress += int(1)
                        self.process_hddp_reply(pkt, eth_header, hddp_header, entry_interface)
                elif (hddp_header["OpCode"] == HDDP_ACK):
                        self.num_packet_ack_ingress += int(1)
                        self.process_hddp_ack_req(pkt, eth_header, hddp_header, entry_interface)
                return

        def print_datas(self):
                text = "MACS Addr: "+str(self.mac_myself)+"\n"
                text +="Interface names: "+str(self.interface_name)+"\n"
                text +="Sockets:"+str(self.inputs)+"\n"
                text +="Ids: "+str(self.ID_Propia)+"\n"
                text +="Block table: "+ str(self.block_table)+"\n"
                text +="ONOS ID: "+str(self.Id_onos)+"("+self.int_to_mac(self.Id_onos)+")\n"
                text +="Device type: "+str(self.type_device)+"\n"
                self.log ("INFO", text);
                return;
        
        def write_data_file(self):
                f = open(str(self.nombre_fichero), "a+")
                f.write(str(self.num_sec)+"\t"+
                        str(self.num_packet_request_exit)+"\t"+
                        str(self.num_packet_reply_ucast_exit)+"\t"+
                        str(self.num_packet_reply_bcast_exit)+"\t"+
                        str(self.num_packet_ack_exit)+"\t"+
                        str(self.num_packet_request_ingress)+"\t"+
                        str(self.num_packet_reply_ucast_ingress)+"\t"+
                        str(self.num_packet_reply_bcast_ingress)+"\t"+
                        str(self.num_packet_ack_ingress)+"\t"+
                        str(self.num_packet_hddp_ingress)+"\t"+
                        str(self.last_timer)+"\t"+
                        str(self.estado)+"\t"+
                        str(self.distance_sdn)+"\n")

                f.close()
                self.num_sec = int(0)
                self.num_packet_request_exit = int(0)
                self.num_packet_reply_ucast_exit = int(0)
                self.num_packet_reply_bcast_exit = int(0)
                self.num_packet_ack_exit = int(0)
                self.num_packet_request_ingress = int(0)
                self.num_packet_reply_ucast_ingress = int(0)
                self.num_packet_reply_bcast_ingress = int(0)
                self.num_packet_ack_ingress = int(0)
                self.num_packet_hddp_ingress = int(0)
                self.last_timer = int(0)
                self.estado = int(0)
                self.distance_sdn = int(0)

        def log(self,Type, mensaje):
                if (self.log_activo):
                        f = open(str(self.nombre_log), "a+")
                        f.write(str(Type)+"->"+str(mensaje)+"\n")
                        f.close()

        def resend_fail_packets(self):
                current_time = time.time() * 1000
                if NUM_RESEND > 0 and len(self.request_waiting_reply.keys()) > 0:
                    list_num_sec = self.request_waiting_reply.keys()
                    for num_sequece_resend_request in list_num_sec:
                        list_timers_request = self.request_waiting_reply[num_sequece_resend_request].keys()
                        for timer_request_resend in list_timers_request:
                            if timer_request_resend + int(self.resend_time) <= current_time and self.request_resent[num_sequece_resend_request] < NUM_RESEND:
                                for interfaz_out in self.request_waiting_reply[num_sequece_resend_request][timer_request_resend].keys():
                                    try:
                                        if not self.message_queues.has_key(interfaz_out):
                                                self.message_queues[interfaz_out] = []
                                        
                                        self.message_queues[interfaz_out].append(
                                                self.request_waiting_reply[num_sequece_resend_request][timer_request_resend][interfaz_out])

                                        if not interfaz_out in self.outputs:
                                                self.outputs.append(interfaz_out)
                                        
                                        self.num_packet_request_exit += int(1)
                                    except Exception as exception:
                                        continue

                                self.request_resent[num_sequece_resend_request] += int(1)
                                
                                if self.request_resent[num_sequece_resend_request] < NUM_RESEND:
                                    self.request_waiting_reply[num_sequece_resend_request][current_time] = self.request_waiting_reply[num_sequece_resend_request].pop(timer_request_resend)
                                    
                            if self.request_resent[num_sequece_resend_request] >= NUM_RESEND:
                                self.request_waiting_reply.pop(num_sequece_resend_request, None)
                                self.request_resent.pop(num_sequece_resend_request, None)
                  
                remove_items = []
                move_time_items = []
                timers = {}
                current_time = time.time() * 1000
                for resend_reply in self.reply_waiting_ack:
                        if int(self.reply_waiting_ack[resend_reply]["time_send"]) + int(self.resend_time) <= current_time:
                                retrans_model = 0

                                if not self.reply_waiting_ack_counter.has_key(resend_reply):
                                    if NUM_RESEND > 0:
                                        retrans_model = 0
                                        self.reply_waiting_ack_counter[resend_reply] = int(1);
                                    else:
                                        if (self.block_table["mac_ant"] != self.reply_waiting_ack[resend_reply]["hddp_header"]["mac_sig"] and 
                                        self.block_table["mac_ant"] != [] and self.block_table["timestamp"] >= current_time):
                                            retrans_model = 1
                                        else:
                                            retrans_model = 2
                                        self.reply_waiting_ack_counter.pop(resend_reply, None);
                                        remove_items.append(resend_reply)
                                elif (self.reply_waiting_ack_counter[resend_reply] < NUM_RESEND):
                                    retrans_model = 0
                                    self.reply_waiting_ack_counter[resend_reply] += int(1);
                                else:
                                    if (self.block_table["mac_ant"] != self.reply_waiting_ack[resend_reply]["hddp_header"]["mac_sig"] and 
                                        self.block_table["mac_ant"] != [] and self.block_table["timestamp"] >= current_time):
                                        retrans_model = 1
                                    else:
                                        
                                        retrans_model = 2
                                    self.reply_waiting_ack_counter.pop(resend_reply, None);
                                    remove_items.append(resend_reply)


                                try:
		                        if (retrans_model == 0):
		                            link_bidi = 1;
		                            hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
		                                    "", self.reply_waiting_ack[resend_reply]["eth_header"], self.reply_waiting_ack[resend_reply]["hddp_header"], HDDP_RESEND, 
		                                    self.reply_waiting_ack[resend_reply]["entry_interface"], self.reply_waiting_ack[resend_reply]["entry_interface"], link_bidi, resend_reply)
		                            self.reply_waiting_ack[resend_reply]["entry_interface"].send(hddp_packet_reply);
		                            self.num_packet_reply_ucast_exit += int(1)
		                            
		                            
		                            self.reply_waiting_ack[resend_reply]["time_send"] += self.resend_time
		                            
		                        elif (retrans_model == 1):
		                            
		                            self.reply_waiting_ack[resend_reply]["hddp_header"]["Num_hops"] = 2
		                            self.reply_waiting_ack[resend_reply]["bidirectionals"][0] = int(bin(int(SIZE_TYPE_DEV-1) << 6 | int(SIZE_ID_MAC-1) << 3 | 
		                                int (SIZE_PORT -1) << 1 | int (0)),2) 
		                            link_bidi = 1;
		                            self.reply_waiting_ack[resend_reply]["hddp_header"]["mac_sig"] = self.block_table["mac_ant"]
		                            self.reply_waiting_ack[resend_reply]["eth_header"]["mac_dst"] = self.block_table["mac_ant"]
		                            hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
		                                    "", self.reply_waiting_ack[resend_reply]["eth_header"], self.reply_waiting_ack[resend_reply]["hddp_header"], HDDP_RESEND, 
		                                    self.reply_waiting_ack[resend_reply]["entry_interface"], self.block_table["interfaz_salida"], link_bidi, resend_reply)
		                            self.block_table["interfaz_salida"].send(hddp_packet_reply);
		                            self.num_packet_reply_ucast_exit += int(1)
		                            
		                        else:
		                            
		                            self.reply_waiting_ack[resend_reply]["hddp_header"]["mac_sig"] = ['0xff','0xff','0xff','0xff','0xff','0xff']
		                            self.reply_waiting_ack[resend_reply]["eth_header"]["mac_dst"] = ['0xff','0xff','0xff','0xff','0xff','0xff']
		                            self.reply_waiting_ack[resend_reply]["hddp_header"]["Num_hops"] = 2
		                            self.reply_waiting_ack[resend_reply]["bidirectionals"][0] = int(bin(int(SIZE_TYPE_DEV-1) << 6 | int(SIZE_ID_MAC-1) << 3 | 
		                                int (SIZE_PORT -1) << 1 | int (0)),2)
		                            link_bidi = 0;
		                            
		                            for out_interface in self.inputs:
		                                    self.reply_waiting_ack[resend_reply]["eth_header"]["mac_src"] = str(self.mac_interface(out_interface)).split(":")
		                                    self.reply_waiting_ack[resend_reply]["hddp_header"]["last_mac"] = str(self.mac_interface(out_interface)).split(":")
		                                    hddp_packet_reply, types, id_devices, inports, outports, bidirectionals = self.create_hddp_packet(
		                                            "", self.reply_waiting_ack[resend_reply]["eth_header"], self.reply_waiting_ack[resend_reply]["hddp_header"], HDDP_RESEND, 
		                                            self.reply_waiting_ack[resend_reply]["entry_interface"], out_interface, link_bidi, resend_reply)                                                      
		                                    out_interface.send(hddp_packet_reply)
		                                    self.num_packet_reply_bcast_exit += int(1)
		                                                                                  


                                except Exception as exception:
                                    remove_items.append(resend_reply)
                                    continue

                for remove_element in remove_items:
                    self.reply_waiting_ack.pop(remove_element, None);
                
 
        def recv(self):
                while True:
                        readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, self.timeout/1000)
                        
                        for interface_readable in readable:
                                try:
                                        eth_header = {}; 
                                        pkt, sa_ll = interface_readable.recvfrom(MTU)
                                
                                        if len(pkt) <= 0:
                                                break

                                        eth_header_data = struct.unpack("!6B6BH", pkt[0:14]);
                                        eth_header["mac_dst"] = [hex(int(eth_header_data[x])) for x in range(0,6)]
                                        eth_header["mac_src"] = [hex(int(eth_header_data[x])) for x in range(6,12)]
                                        eth_header["eth_type"] = (int(eth_header_data[12]))

                                        if sa_ll[2] == socket.PACKET_OUTGOING: 
                                                continue
                                        if (eth_header["eth_type"] != ETH_HDDP): 
                                                continue

                                        hddp_header = pkt[14:len(pkt)] 
                                        
                                        self.process_hddp_frame(pkt, eth_header, hddp_header, interface_readable)
                                        
                                except Exception as exception:
                                        continue                       
                        
                        self.resend_fail_packets()
                                                
                        for interface_writable in writable:
                                for msg in range (0, len(self.message_queues[interface_writable])):
                                        try:
                                                interface_writable.send(self.message_queues[interface_writable][msg]);
                                        except Exception as exception:
                                                continue
                                try: 
                                    if self.message_queues.has_key(interface_writable):
                                        self.message_queues.pop(interface_writable,None)
                                    
                                    if interface_writable in self.outputs:
                                        self.outputs.remove(interface_writable)
                                except Exception as exception:
					continue


hddp_sniff = hddp_sniffer()

num_wlan = int(0)
num_eth = int(0)

lista_intf = os.listdir('/sys/class/net/')
for interface in lista_intf:
        if interface.find("lo") != -1:
                continue; 
        elif interface.find("wlan") != -1:
                num_wlan += int(1)
        else:
                num_eth += int(1)
        fd = open('/sys/class/net/'+str(interface)+"/address","r")
        mac_interface = str(fd.read().split("\n")[0])
        hddp_sniff.insert_interfaces(interface, mac_interface)
        


hddp_sniff.insert_type_device(num_wlan, num_eth);
hddp_sniff.set_active_log (LOG_ACTIVO)
hddp_sniff.insert_file_name("sta"+str(hddp_sniff.get_id_onos())+".txt")
hddp_sniff.print_datas()
if (sys.argv[1]):
    NUM_RESEND = int(sys.argv[1])

hddp_sniff.recv()
