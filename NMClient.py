import argparse
from struct import unpack
import socket
import sys

DATA_CHUNK = 1460
TLV_HDR_SIZE = 3
TLV_HDR_FORMAT = "!BH"
TLV_N_MSG = 1
TLV_IP_DATA = 2
TLV_MAC_DATA = 3
TLV_STATE_DATA = 4


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server_addr", type=str,
        help="address of the server")
    parser.add_argument("--server_port", type=int,
        help="port of the server")
    args = parser.parse_args()
    return args

class NeighborStateMsg(object):
    def __init__(self, state, ip, mac=None):
        self.state = state
        self.ip = ip
        self.mac = mac

class NMClient(object):
    def __init__(self, server_ip, server_port):
        self._server_ip = server_ip
        self._server_port = server_port
    
    def run(self):
        self._init_connection()
        self._start_msg_handling()

    def _init_connection(self):
        #TODO(tehnerd): logick to handle AF_INET or AF_INET6
        print(self._server_ip)
        print(self._server_port)
        self._client_socket = socket.socket()
        try:
            self._client_socket.connect((self._server_ip, self._server_port))
        except:
            print("cant connect to server")
            raise

    def _deserialize_tlv(self, tlv):
        msg_type, msg_len = unpack(TLV_HDR_FORMAT, tlv)
        return msg_type, msg_len

    def _deserialize_msg(self, msg):
        # arista sending string in ascii encoding format (python2)
        msg_type, msg_len = self._deserialize_tlv(msg[:TLV_HDR_SIZE])
        if msg_len + TLV_HDR_SIZE > len(msg):
            # we have received only part of the msg
            return None, msg
        else:
            msg_tail = msg[msg_len+TLV_HDR_SIZE:]
            msg = msg[TLV_HDR_SIZE:msg_len+TLV_HDR_SIZE]
        # now we do know, that we have received whole msg 
        # and we can start to unpack it
        nsm = NeighborStateMsg(state="new msg", ip=-1)
        while len(msg) > 0:
            tlv_type, tlv_len = self._deserialize_tlv(msg[:TLV_HDR_SIZE])
            if TLV_HDR_SIZE + tlv_len > len(msg):
                nsm.state = "error"
                return nsm
            msg = msg[TLV_HDR_SIZE:]
            if tlv_type == TLV_IP_DATA:
                nsm.ip = msg[:tlv_len].decode('ascii')
            elif tlv_type == TLV_MAC_DATA:
                nsm.mac = msg[:tlv_len].decode('ascii')
            elif tlv_type == TLV_STATE_DATA:
                nsm.state = msg[:tlv_len].decode('ascii')
            msg = msg[tlv_len:]
        return nsm, msg_tail
            
            

    def _start_msg_handling(self):
        # testing on python3; easy to chagne for 2
        msg=b""
        while True:
            data = self._client_socket.recv(DATA_CHUNK)
            msg+=data
            while True:
                if len(msg) < TLV_HDR_SIZE:
                    break
                nsm, msg = self._deserialize_msg(msg)
                if nsm is None:
                    break
                print("recv state {} for ip {} and mac {}".format(
                    nsm.state,
                    nsm.ip,
                    nsm.mac))


if __name__ == "__main__":
    args = parse_args()
    if args.server_addr is None:
        print("server_addr is mandatory")
        sys.exit(-1)
    if args.server_port is None:
        print("server_port is mandatory")
        sys.exit(-1)
    nmc = NMClient(args.server_addr, args.server_port)
    nmc.run()
