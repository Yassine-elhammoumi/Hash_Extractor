# Hash Extractor

This python script `hash_extractor.py` is fed a capture file and outputs hashes extracted from kerberos or ntlmssp conversations in a format that can be used by [hashcat](https://github.com/hashcat/hashcat). 

## Prerequisites :

- **Tshark** needs to be installed.

for Debian systems :

```bash
sudo apt install tshark
```

[More information and installations methods](https://tshark.dev/setup/install/)

- **Python > 3.10**

- **pyshark** python package

```bash
pip install pyshark
```

You also need **[hashcat](https://github.com/hashcat/hashcat)** to crack the hashes extracted from the script.


## Usage :

### Kerberos

Supported [etypes](https://ldapwiki.com/wiki/Wiki.jsp?page=Kerberos%20Encryption%20Types) (normal salts) : 
    - AES256-CTS-HMAC-SHA1-96 (Type 18)
    - RC4-HMAC (Type 23)

- Extract the hashes :

```bash
python3 hash_extractor.py kerberos <pcap file> <output file>
```

- Crack the hashes (example) :

```bash
hashcat -m \#\#\#\# hash.txt wordlist.txt
```

    - etype 18 : 19900
    - etype 23 : 7500



### ntlmssp

- Extract the hashes :

```bash
python3 hash_extractor.py ntlmssp <pcap file> <output file>
```

- Crack the hashes (example) :

```bash
hashcat -m 5600 hash.txt wordlist.txt
```

