import pyshark
import sys

def kerb_hash(file, out_file) :

    with open(out_file, 'w') as o_file: pass

    out = open(out_file, "a", encoding="utf-8")

    try :
        cap = pyshark.FileCapture(file, display_filter='kerberos.msg_type == 10')
    except FileNotFoundError :
        print("Capture file does not exist.")
        sys.exit(1)

    for packet in cap :

        try :
            user = packet.kerberos.get("CNameString")

            domain = packet.kerberos.get("realm")

            if (etype := packet.kerberos.get("etype")) not in ["18", "23"]:
                continue
        
            enc_part = packet.kerberos.get("cipher").replace(":", "")

            if etype == "23" :
                enc_part = enc_part[32:] + enc_part[:32] 

        except :
            continue

        hash = ""

        if etype == "18" :
            hash = f"$krb5pa${etype}${user}${domain}${enc_part}"
        else :
            hash = f"$krb5pa${etype}${user}${domain}${domain}${user}${enc_part}"

        out.write(hash + "\n")

    out.close()


def ntlm_hash(file, out_file) :

    with open(out_file, 'w') as o_file: pass

    out = open(out_file, "a", encoding="utf-8")

    try :
        cap = pyshark.FileCapture(file, display_filter="ntlmssp")
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

        out.write(username + "::" + domain + ":" + challenge + ":" + response[:32] + ":" + response[32:] + "\n")

if __name__ == '__main__':

    print("░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░             ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓███████▓▒░             ")
    print("░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░                   ")
    print("░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░                   ")
    print("░▒▓█▓▒░       ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░                   ")
    print("                                                                 ")
    print("                                                                 ")
    print("░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓████████▓▒░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░            ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░            ")
    print("                                                                 ")
    print("                                                                 ")
    print("░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░             ")
    print("░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓██████▓▒░  ░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░             ")
    print("░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░            ")
    print("                                                                 ")
    print("                                                                 ")
    print(" ░▒▓██████▓▒░ ░▒▓██████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░  ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
    print("░▒▓████████▓▒░▒▓█▓▒░        ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
    print("░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
    print("░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ ")
    print("                                                                 ")
    print("                                                                 ")
    

    args = sys.argv[1:]

    if len(args) != 3:

        print("==> [1] Extract NTLMSSP hashes")
        print("==> [2] Extract Kerberos hashes\n\n")
        type_hash = input("==> # ")

        if type_hash == "1" :
            type_hash = "ntlmssp"
        elif type_hash == "2" :
            type_hash = "kerberos"
        else :
            print("Indefined input")
            sys.exit(1)

        print("\n==> You've selected: " + type_hash + "\n\n")

        input_file = input("==> input file :\n==> # ")
        print("\n==> input file = " + input_file +"\n\n")

        output_file = input("==> output file :\n==> # ")
        print("\n==> output file = " + output_file +"\n\n")

    else :
        print("==> Arguments provided, Skipping setup...")
        input_file = args[1]
        output_file = args[2]
        type_hash = args[0]

    
    if type_hash == "ntlmssp" :
        ntlm_hash(input_file, output_file)
    elif type_hash == "kerberos" :
        kerb_hash(input_file, output_file)
    else :
        print("invalid type")
        sys.exit(1)
