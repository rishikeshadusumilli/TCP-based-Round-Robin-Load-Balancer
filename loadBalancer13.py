#!/bin/bash

#Code adopted and implemented from Nippon Telegraph and Telephone Corporation.
#Code adopted and implemented from simple_switch_13.py

#Copyright Rishikesh Adusumilli

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import random
from ryu.lib import dpid as dpid_lib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib import mac as mac_lib
from ryu.lib import ip as ip_lib
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.ofproto import ether, inet
from ryu.lib.packet import tcp
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3


class loadBalancer13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(loadBalancer13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

############Assigning IP address to TCP servers (H1, H2, and H3)
       
        self.serverIP1="10.0.0.1"
        self.serverMac1="00:00:00:00:00:01"
        self.serverIP2="10.0.0.2"
        self.serverMac2="00:00:00:00:00:02"
        self.serverIP3="10.0.0.3"
        self.serverMac3="00:00:00:00:00:03"

############Count to indicate which server to use for TCP session. H1=1, H2=2, H3=3

        self.serverCount=1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

############Generate ARP reply packet for ARP request to controller (IP: 10.0.0.100).
#srcMac can be any value to set controller MAC address for controller IP address.

    def arpReplyGenerate(self, dstMac, dstIp):
        srcMac = "11:22:33:ab:cd:ef"
        srcIp = "10.0.0.100"

        packetReply = packet.Packet()
        etherReply = ethernet.ethernet(dstMac, srcMac,0x0806)
        arpReply = arp.arp(1,0x0800,6,4,2,srcMac,srcIp,dstMac,dstIp)
        packetReply.add_protocol(etherReply)
        packetReply.add_protocol(arpReply)
        packetReply.serialize()

        return packetReply

############Module to receive Packet-In

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("\n packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("\n Packet-In - DPID: %s SMAC: %s DMAC: %s InPort: %s", dpid, src, dst, in_port)

############ARP Reply handling
#Send ARP reply for ARP request to controller (IP: 10.0.0.100)

        if(eth.ethertype==0x0806):

            self.logger.info("\n Reached inside of first ARP type check-------->")
            arpContents=pkt.get_protocols(arp.arp)[0]
            if((arpContents.dst_ip=="10.0.0.100")and(arpContents.opcode==1)):
                self.logger.info("\n Reached inside of ARP reply for 10.0.0.100-------->")
                packetReply=self.arpReplyGenerate(arpContents.src_mac,arpContents.src_ip)
                actionsServer=[parser.OFPActionOutput(in_port)]
                arpServer=parser.OFPPacketOut(datapath=datapath,in_port=ofproto.OFPP_ANY,data=packetReply.data,actions=actionsServer,buffer_id=0xffffffff)

                self.logger.info("\n Packet-Out - DPID: %s SMAC: 11:22:33:ab:cd:ef DMAC: %s OutPort: %s", dpid, src, in_port) 

                datapath.send_msg(arpServer)
            return

############TCP Host to Server
#Assign TCP server to the host request depending on the count of the TCP request
#Entire TCP session is assigned and handled by a single server based on count
#S1 or H1 is used as server for count of 1
#S2 or H2 is used as server for count of 2
#S3 or H3 is used as server for count of 3

        self.logger.info("\n Reached inside of first TCP type check-------->")

        if(self.serverCount==1):
            serverIP=self.serverIP1
            serverMac=self.serverMac1
        elif(self.serverCount==2):
            serverIP=self.serverIP2
            serverMac=self.serverMac2
        elif(self.serverCount==3):
            serverIP=self.serverIP3
            serverMac=self.serverMac3        

        if(eth.ethertype==0x0800):
            ipContents=pkt.get_protocols(ipv4.ipv4)[0]
            if((ipContents.dst=="10.0.0.100")and(ipContents.proto==0x06)):
                tcpContents=pkt.get_protocols(tcp.tcp)[0]

#Perform TCP action only if matching TCP properties
                match1=parser.OFPMatch(in_port=in_port,eth_type=eth.ethertype,eth_src=eth.src,eth_dst=eth.dst,ip_proto=ipContents.proto,ipv4_src=ipContents.src,ipv4_dst=ipContents.dst,tcp_src=tcpContents.src_port,tcp_dst=tcpContents.dst_port)

#Send host TCP segments to destination server using destination server port connected to controller
                actions1=[parser.OFPActionSetField(ipv4_src="10.0.0.100"),parser.OFPActionSetField(eth_dst=serverMac),parser.OFPActionSetField(ipv4_dst=serverIP),parser.OFPActionOutput(self.serverCount)]

                ipInst1=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions1)] 
                cookie1=random.randint(0, 0xffffffffffffffff)

#Create flow for incoming TCP segments from host to server through controller (IP: 10.0.0.100)
                flowMod1=parser.OFPFlowMod(datapath=datapath,match=match1,idle_timeout=7,instructions=ipInst1,buffer_id=msg.buffer_id,cookie=cookie1)

                self.logger.info("\n Added flow for Host to Server condition------->")
                self.logger.info("\n Application on server"+str(self.serverCount)+" - IP: "+str(serverIP)+" Mac: "+str(serverMac))

                self.logger.info("\n Client-LB - SIP: "+str(ipContents.src)+" DIP: "+str(ipContents.dst))

                self.logger.info("\n LB-Server - SIP: 10.0.0.100 DIP: "+str(serverIP))

#Add flow in the flow table of the virtual switch

                datapath.send_msg(flowMod1)

############TCP Server to Host

#Perform TCP action only if matching TCP properties
                match2=parser.OFPMatch(self.serverCount,eth_type=eth.ethertype,eth_src=serverMac,eth_dst="11:22:33:ab:cd:ef",ip_proto=ipContents.proto,ipv4_src=serverIP,ipv4_dst="10.0.0.100",tcp_src=tcpContents.dst_port,tcp_dst=tcpContents.src_port)

#Send server TCP segments to host using source host port connected to controller
                actions2=[parser.OFPActionSetField(eth_src="11:22:33:ab:cd:ef"),parser.OFPActionSetField(ipv4_src="10.0.0.100"),parser.OFPActionSetField(eth_dst=eth.src),parser.OFPActionSetField(ipv4_dst=ipContents.src),parser.OFPActionOutput(in_port)]

                ipInst2=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions2)] 

                cookie2=random.randint(0, 0xffffffffffffffff)

#Create flow for TCP segments from server to host through controller (IP: 10.0.0.100)
     flowMod2=parser.OFPFlowMod(datapath=datapath,match=match2,idle_timeout=7,instructions=ipInst2,cookie=cookie2)

                self.logger.info("\n Server-LB - SIP: "+str(serverIP)+" DIP: 10.0.0.100")

                self.logger.info("\n LB-Client - SIP: 10.0.0.100 DIP: "+str(ipContents.src))

#Add flow in the flow table of the virtual switch

                datapath.send_msg(flowMod2)

                self.logger.info("\n Added flow for Server to Host condition------->")

############Server Count increment
#Increase count so the next server will serve the next TCP connection from different or same host (When it completes the current TCP session with current TCP server)

        self.serverCount+=1
        if(self.serverCount>3):
            self.serverCount=1
       
