import pyshark
import sys


try :
    cap = pyshark.FileCapture("ntlm_auth.pcapng", display_filter="ntlmssp")
except FileNotFoundError :
    print("Capture file does not exist.")
    sys.exit(1)

exchanges = {}


for packet in cap :

    match str(packet.layers) :                                                                                      # Checking what application layer handles the NTLM authentication
        case str(x) if '<SMB2 Layer>' in x :
            packet_app = packet.smb2
        case str(x) if '<SMB Layer>' in x :
            packet_app = packet.smb
        case str(x) if '<HTTP Layer>' in x :
            packet_app = packet.http

    try :

        if packet.tcp.stream not in exchanges :                                                                     # To differentiate between different 
            exchanges[packet.tcp.stream] = {}                                                                       # NTLMSSP exchanges

        match packet_app.ntlmssp_messagetype :
            case "0x00000003":
                exchanges[packet.tcp.stream]["username"] = packet_app.ntlmssp_auth_username                         # Getting the username
                if packet_app.ntlmssp_auth_domain == "NULL" :                                                       # Getting the domain
                    exchanges[packet.tcp.stream]["domain"] = ""
                else :
                    exchanges[packet.tcp.stream]["domain"] = packet_app.ntlmssp_auth_domain
                exchanges[packet.tcp.stream]["response"] = packet_app.ntlmssp_auth_ntresponse.replace(":", "")      # Getting the response
            case "0x00000002":
                exchanges[packet.tcp.stream]["challenge"] = packet_app.ntlmssp_ntlmserverchallenge.replace(":", "") # Getting the challenge


    except Exception as e:
        print(e)
        pass

for tcp_stream in list(exchanges.keys()) :              # Found out sometimes exchanges wouldn't have
    if exchanges[tcp_stream]["username"] == "NULL" :    # a username and thus wouldn't work with hashcat
        exchanges.pop(tcp_stream)                       # So I removed them

for tcp_stream in exchanges.keys() :
    username = exchanges[tcp_stream]["username"]
    domain = exchanges[tcp_stream]["domain"]
    response = exchanges[tcp_stream]["response"]
    challenge = exchanges[tcp_stream]["challenge"]

    print(username + "::" + domain + ":" + challenge + ":" + response[:32] + ":" + response[32:])


