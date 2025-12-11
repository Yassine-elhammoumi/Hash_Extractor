import pyshark
import sys

def kerb_hash(file) :
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

        print(hash)

if __name__ == '__main__':
    args = sys.argv[1:]

    if len(args) != 1:
        print("Usage: python kerb_hash.py <pcap_file>")
        sys.exit(1)

    kerb_hash(args[0])