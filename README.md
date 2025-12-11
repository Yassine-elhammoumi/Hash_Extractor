## Kerberos hash extractor (from capture file)

This python script is fed a capture file and prints kerberos Pre-Authentication hashes in a format that is crackable using hashcat.

Supported [etypes](https://ldapwiki.com/wiki/Wiki.jsp?page=Kerberos%20Encryption%20Types) (normal salts) : 
    - AES256-CTS-HMAC-SHA1-96 (Type 18)
    - RC4-HMAC (Type 23)


### Prerequisites :

- **Tshark** needs to be installed.

for Debian systems :

```bash
sudo apt install tshark
```

[More information and installations methods](https://tshark.dev/setup/install/)

- **Python > 3.8**

- **pyshark** python package

```bash
pip install pyshark
```

You also need **hashcat** to crack the hashes extracted from the script.


### Usage :

- Extract the hashes :

```bash
python3 kerb_hash.py <pcap_file>
```

- Crack the hashes :

```bash
hashcat -m \#\#\#\# hash.txt wordlist.txt
```

    - etype 18 : 19900
    - etype 23 : 7500

