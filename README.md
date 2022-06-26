```
    __ _ ___ _ __  ___  ___ __ _ _ __
   / _` / __| '_ \/ __|/ __/ _` | '_ \
  | (_| \__ \ | | \__ \ (_| (_| | | | |
   \__,_|___/_| |_|___/\___\__,_|_| |_|
    v1.0         Scan all the things..

 This tool will allow you to look up all IP address ranges assigned
 to an ASN, as well as any associated downstreams.  From there you
 can either initiate a scan of the address ranges, or you can abort
 and be provided with a list of ASNs and IP ranges that were found.

 SCANS REQUIRE CUSTOMIZATION of the asnworker.py file.  There is an
 example of a scan using a non-cidr aware app (curl + grep output) as
 well as a cidr aware app (nmap).  The nmap scan is setup in a way that
 it requires elevation (sudo).  You can customize the nmap command line
 as you see fit.  You can also add as many custom scan types as you choose.  
 Scan types don't have to be scans.  For instance, you could create a
 multi-step scan that includes payload delivery only if certain conditions
 were met.


 Usage
 ./asnscan.sh <SCANTYPE/MODE> <ASN/FOLDER/FILE>


 Default and custom <SCANTYPES> are set in the asnworker.py file.  You should
 open and edit this file to suit your needs.  The default nmap scan will work
 for most (provided you can sudo), but the curl scan will definately require 
 customization to fit your needs. You can add custom scan types or even use
 this for payload delivery in addition to scanning.
 

 <SCANTYPE> options
  - curl      Use curl to send a request and validate the response
                ./asnscan.sh curl AS1234
                ./asnscan.sh curl 1234
  - nmap      Use nmap to scan the ranges
                ./asnscan nmap AS1234
                ./asnscan.sh nmap 1234


 <MODE> options
  - resume    Resume a scan using the original AS number that was used when
              the scan was started OR the scan data folder name
                ./asnscan.sh resume AS1234
                ./asnscan.sh resume mylist.txt-manual
  - manual    Manually scan a list of IP ranges from a file located in
              in the SAME FOLDER as asnscan.sh (don't use a full path here)
                ./asnscan.sh manual iplist.txt
```

# Dependencies

   - Net Consolidator - https://github.com/TKCERT/net-consolidator
   - BGPview.io CLI Client - https://github.com/jayswan/bgpview
   - General Linux Utils (text utils, bc, whois, etc. - check the dependency paths section in asnscan.sh for a full list
