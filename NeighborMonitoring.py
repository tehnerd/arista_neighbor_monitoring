#!/usr/bin/env python

from collections import defaultdict
import eossdk
import exceptions
import multiprocessing
import select
import socket
import struct
import sys
import time


# subscribers server constants
EPOLL_READ_ONLY = (
                   select.EPOLLIN |
                   select.EPOLLPRI |
                   select.EPOLLHUP |
                   select.EPOLLERR
                  )

EPOLL_READ_WRITE = (
                    EPOLL_READ_ONLY |
                    select.EPOLLOUT
                   )
EPOLL_TIMEOUT=1
ANY_ADDR=""
NON_BLOCKING = 0
SUB_PORT = 2307
MAX_CLIENTS_CONNECTIONS = 256
DATA_CHUNK = 1460
MAX_MSG_SIZE = 1<<16-1
TLV_HDR_SIZE = 3
TLV_HDR_FORMAT = "!BH"
TLV_N_MSG = 1
TLV_IP_DATA = 2
TLV_MAC_DATA = 3
TLV_STATE_DATA = 4

class NeighborStateMsg(object):
    def __init__(self, state, ip, mac=None):
        self.state = state
        self.ip = ip
        self.mac = mac

class NeighborMonitor(eossdk.AgentHandler, eossdk.NeighborTableHandler):
    def __init__(self, nbrMgr, agentMgr):
        eossdk.AgentHandler.__init__(self, agentMgr)
        eossdk.NeighborTableHandler.__init__(self, nbrMgr)
        self.tracer = eossdk.Tracer("EosSdkNeighborMonitor")
        self.nbrMgr_ = nbrMgr
        self.agentMgr_ = agentMgr

        # Keep track of the total number of state changes. This number
        # gets reset whenever the agent is restarted.
        self.numNbrChanges_ = 0

        self.tracer.trace0("Constructed")

        # To notify external subscribers
        self._msg_queue = multiprocessing.Queue()

        # for epoll dict fd to socket
        self._sock_dict = {}

    def on_initialized(self):
        self.tracer.trace0("We are initialized!")
        self.agentMgr_.status_set("Total nbr changes", "0")
        self.watch_all_neighbor_entries(True)
        neighbor_iter = self.nbrMgr_.neighbor_table_iter()
        multiprocessing.Process(
            target=self._subscribers_handler,
            args=()).start()
        for neighbor in neighbor_iter:
            self.tracer.trace1("adding neighbor")
            self.numNbrChanges_ += 1
            entry = self.nbrMgr_.neighbor_entry(neighbor)
            if entry:
                self._msg_queue.put(NeighborStateMsg(state="add",
                    ip=neighbor.ip_addr().to_string(),
                    mac=entry.eth_addr().to_string()))
    
    def on_neighbor_entry_set(self, entry):
        self.numNbrChanges_ += 1
        neighbor_key = entry.neighbor_key()
        ip_addr = neighbor_key.ip_addr()
        eth_addr = entry.eth_addr()
        self.agentMgr_.status_set("Total nbr changes", str(self.numNbrChanges_))
        self._msg_queue.put(NeighborStateMsg(state="add",
            ip=ip_addr.to_string(),
            mac=eth_addr.to_string()))

    def on_neighbor_entry_del(self, key):
        self.numNbrChanges_ += 1
        ip_addr = key.ip_addr()
        self._msg_queue.put(NeighborStateMsg(state="del",
            ip = ip_addr.to_string()))
    
    def _serialize_msg(self, msg):
        # we are going to use TLV framing
        # w/ 1 byte type and 2 bytes length
        # type = 1 - msg wraper
        # type = 2 - ip addr
        # type = 3 - mac addr
        # type = 4 - state
        # so msg will looks like
        # [1; len of msg][2; len of ip][ip][(if not del)3;len of mac][4; len of
        # state]
        if len(msg.ip) > MAX_MSG_SIZE:
            # bigger than max lenght field in tlv
            raise
        if len(msg.state) > MAX_MSG_SIZE:
            # bigger than max lenght field in tlv
            raise
        if msg.mac is not None:
            if len(msg.mac) > MAX_MSG_SIZE:
                # bigger than max lenght field in tlv
                raise
            mac_tlv = struct.pack(TLV_HDR_FORMAT, TLV_MAC_DATA, len(msg.mac))
        else:
            msg.mac = ""
            mac_tlv = ""
        ip_tlv = struct.pack(TLV_HDR_FORMAT, TLV_IP_DATA, len(msg.ip))
        state_tlv = struct.pack(TLV_HDR_FORMAT, TLV_STATE_DATA, len(msg.state))
        payload = "".join((ip_tlv, msg.ip,
             mac_tlv, msg.mac,
             state_tlv, msg.state))
        if (len(payload) + TLV_HDR_SIZE) > MAX_MSG_SIZE:
            raise
        msg_hdr = struct.pack(TLV_HDR_FORMAT, TLV_N_MSG, len(payload))
        return "".join((msg_hdr, payload))

    def _init_server(self):
        self._ssocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._ssocket.setblocking(NON_BLOCKING)
        sserv_addr = (ANY_ADDR, SUB_PORT)
        self._ssocket.bind(sserv_addr)
        self._ssocket.listen(MAX_CLIENTS_CONNECTIONS)
        self._poller = select.epoll()
        self._poller.register(self._ssocket, EPOLL_READ_ONLY)
        self._sock_dict[self._ssocket.fileno()] = self._ssocket

    def _handle_new_msg(self, msg, neighbor_dict, per_subscriber_msg_queue):
        print("new msg: {} {} {} ".format(msg.state, msg.ip, msg.mac))
        self.tracer.trace1("new msg received")
        if msg.state == "add":
            neighbor_dict[msg.ip] = msg
        elif msg.state == "del":
            if msg.ip in neighbor_dict:
                del(neighbor_dict[msg.ip])
        for subscriber in per_subscriber_msg_queue:
            self._poller.modify(self._sock_dict[subscriber], EPOLL_READ_WRITE)
            per_subscriber_msg_queue[subscriber].append(msg)

    def _handle_new_connection(self, neighbor_dict, per_subscriber_msg_queue):
        conn, conn_addr = self._ssocket.accept()
        print("connection from {}".format(conn_addr,))
        conn.setblocking(0)
        self._sock_dict[conn.fileno()] = conn
        per_subscriber_msg_queue[conn.fileno()] = []
        if len(neighbor_dict) != 0:
            for k in neighbor_dict:
                per_subscriber_msg_queue[conn.fileno()].append(neighbor_dict[k])
            self._poller.register(conn, EPOLL_READ_WRITE)
        else:
            self._poller.register(conn, EPOLL_READ_ONLY)

    def _send_data_to_subscriber(self, sock,
            per_subscriber_msg_queue, per_subscriber_data_to_send):
        sd = sock.fileno()

        if( sd in per_subscriber_data_to_send  or
           len(per_subscriber_msg_queue[sd]) == 0):
            # no more data to send
            print("no more data")
            self._poller.modify(sock, EPOLL_READ_ONLY)
            return
        if(sd in per_subscriber_data_to_send and 
                len(per_subscriber_data_to_send[sd]) > 0):
            data = per_subscriber_data_to_send[sd]
            n = sock.send(data)
            if len(data) > n:
                # not all data has been sent
                # will return to this on next iteration
                per_subscriber_data_to_send[sd] = data[n:]
            else:
                del(per_subscriber_data_to_send[sd])
            return
        if(len(per_subscriber_msg_queue[sd]) > 0):
            msg = per_subscriber_msg_queue[sd].pop(0)
            data = self._serialize_msg(msg)
            n = sock.send(data)
            if len(data) > n:
                # not all data has been sent
                per_subscriber_data_to_send[sd] = data[n:]
            return

    def _close_subscribers_connection(self, sock,
            per_subscriber_msg_queue, per_subscriber_data_to_send):
        self._poller.unregister(sock)
        del(self._sock_dict[sock.fileno()])
        if sock.fileno() in per_subscriber_msg_queue:
            del(per_subscriber_msg_queue[sock.fileno()])
        if sock.fileno() in per_subscriber_data_to_send:
            del(per_subscriber_data_to_send[sock.fileno()])
        sock.close()

    def _subscribers_handler(self):
        neighbor_dict = {}
        per_subscriber_msg_queue = defaultdict(list)
        per_subscriber_data_to_send = {}
        self._init_server()
        while True:
            try:
                msg = self._msg_queue.get_nowait()
            except:
                # empty queue
                msg = None
            if msg is not None:
                self._handle_new_msg(
                    msg,
                    neighbor_dict,
                    per_subscriber_msg_queue)
            events = self._poller.poll(EPOLL_TIMEOUT)
            for fd, flag in events:
                sock = self._sock_dict[fd]
                if flag & (select.EPOLLIN | select.EPOLLPRI):
                    if sock is self._ssocket:
                        # new connection
                        self._handle_new_connection(
                            neighbor_dict,
                            per_subscriber_msg_queue
                        )
                    else:
                        data = sock.recv(DATA_CHUNK)
                        if data:
                            # existing client write something to use
                            # totally unexpected.
                            # so we will just read and ignore it
                            print("msg {}".format(data,))
                        else:
                            # connection closed from other side
                            self._close_subscribers_connection(
                                sock,
                                per_subscriber_msg_queue,
                                per_subscriber_data_to_send,
                            )
                elif flag & select.EPOLLHUP:
                    # something went wrong, socket died
                    raise 
                elif flag & select.EPOLLOUT:
                    self._send_data_to_subscriber(
                        sock,
                        per_subscriber_msg_queue,
                        per_subscriber_data_to_send,
                    )
                elif flag & select.EPOLLERR:
                    self._close_subscribers_connection(
                        sock,
                        per_subscriber_msg_queue,
                        per_subscriber_data_to_send,
                    )

         
      
if __name__ == "__main__":
    sdk = eossdk.Sdk()
    _ = NeighborMonitor(sdk.get_neighbor_table_mgr(), sdk.get_agent_mgr())
    sdk.main_loop(sys.argv)
