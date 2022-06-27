#!/bin/bash
#
#    __ _ ___ _ __  ___  ___ __ _ _ __
#   / _` / __| '_ \/ __|/ __/ _` | '_ \
#  | (_| \__ \ | | \__ \ (_| (_| | | | |
#   \__,_|___/_| |_|___/\___\__,_|_| |_|
#    v1.0         Scan all the things..
#
#
# Usage
# ./asnscan.sh <SCANTYPE/MODE> <ASN/FOLDER/FILE>
#
#
# Default and custom <SCANTYPES> are set in the asnworker.py file.  You should
# open and edit this file to suit your needs.  The default nmap scan set there
# will work for most, but the curl scan will definately require customization.
# You can add your own scan types in this file (and could include a payload).
#
#
# <SCANTYPE> options
#  - curl      Use curl to send a request and validate the response
#                ./asnscan.sh curl AS1234
#                ./asnscan.sh curl 1234
#  - nmap      Use nmap to scan the ranges
#                ./asnscan nmap AS1234
#                ./asnscan.sh nmap 1234
#
#
# <MODE> options
#  - resume    Resume a scan using the original AS number that was used when
#              the scan was started OR the scan data folder name
#                ./asnscan.sh resume AS1234
#                ./asnscan.sh resume mylist.txt-manual
#  - manual    Manually scan a list of IP ranges from a file located in
#              in the SAME FOLDER as asnscan.sh (don't use a full path here)
#                ./asnscan.sh manual iplist.txt
#
#
#
#
#
# Dependencies / Requirements
#   - net-consolidator.py - https://github.com/TKCERT/net-consolidator
#   - bgpview.py - https://github.com/jayswan/bgpview
#   - check dependency paths below for a full list of other apps which can
#     all be installed using normal distro tools (apt, etc.)


# ------SETTINGS------
# thread launch delay (spreads cpu/bandwidth load)
export tlaunchdelay=0.33
# dependency paths (python scripts referenced below should be set executable (+x))
export ncpath="./net-consolidator.py"
export bgpath="./bgpview.py"
export grpath="/usr/bin/grep"
export copath="/usr/bin/comm"
export wipath="/usr/bin/whois"
export dapath="/usr/bin/date"
export sppath="/usr/bin/split"
export pspath="/usr/bin/ps"
export bcpath="/usr/bin/bc"
export trpath="/usr/bin/tr"
export cupath="/usr/bin/cut"
export wcpath="/usr/bin/wc"
export capath="/usr/bin/cat"
export sopath="/usr/bin/sort"
export unpath="/usr/bin/uniq"
export tepath="/usr/bin/tee"
export tapath="/usr/bin/tail"
export sepath="/usr/bin/sed"
export hepath="/usr/bin/head"




# environment variables
export scantype=$1
export asn=$2

# dependency check for 3d party python scripts
if [ ! -f $ncpath ]; then
	echo ""
	echo "ERROR: net-consolidator.py was not found!"
	echo "Link: htt$pspath://github.com/TKCERT/net-consolidator"
	echo ""
	echo ""
	echo ""
	exit 1
fi
if [ ! -f $bgpath ]; then
	echo ""
	echo "ERROR: bgpview.py was not found!"
	echo "Link: https://github.com/jayswan/bgpview"
	echo ""
	echo ""
	echo ""
	exit 1
fi

# commandline check
if [ -z "$1" ]; then
	$hepath -n 38 $0
	exit 1
fi
if [ -z "$2" ]; then
	$hepath -n 38 $0
	exit 1
fi

# functions
function do_scan {
	echo "Please enter the number of threads to use (max: 10000):"
	read threadcount
	mkdir $asn/temp > /dev/null 2>&1
	cd $asn/temp
	rm -rf ./*
	sptemp=$(echo "$listlength / $threadcount" | $bcpath)
	splitcount=$(echo "$sptemp + 1" | $bcpath)
	$sppath -d -a 4 -l $splitcount ../$asn-iplist.txt ""
	cd ../..
	echo ""
	echo [Starting $threadcount Scanning Threads]
	touch $asn/$asn-results.txt
	for t in $(ls $asn/temp/); do
		sleep $tlaunchdelay
		( ./asnworker.py $scantype $asn/temp/$t | $tepath -a $asn/$asn-results.txt ) > /dev/null 2>&1 &
	done
	read -p "Monitor scan progress in the foreground (y/n)?" -n 1 -r
	echo ""
	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		echo ""
		echo ""
		echo ""
		echo Please monitor $asn/$asn-results.txt for status/details
		echo note: this file only updates when a full range completes
		echo ""
		echo ""
		echo To check currently running threads you can count the remaining files
		echo in the $asn/temp/ folder, or you can run:
		echo "ps ax | grep asnworker | grep $asn | grep -v grep | wc -l"
		echo ""
		echo ""
		echo ""
		echo ""
		exit 0
	fi
	tcount=$($pspath ax | $grpath asnworker | $grpath $asn | $grpath -v grep | $wcpath -l)
	while [ "$tcount" -gt "0" ]; do
		tcount=$($pspath ax | $grpath asnworker | $grpath $asn | $grpath -v grep | $wcpath -l)
		icount=$($capath $asn/temp/* | $wcpath -l)
		ptmp=$(echo "scale=4;(($tcount/$threadcount)-1) * 100" | $bcpath | $trpath -d \-)
		progress=$(echo "scale=2;($ptmp)/1" | $bcpath)
		psleeptmp=$psleep
		psleep=$(echo "$tcount * 8" | $bcpath)
		if [ "$psleep" = "$psleeptmp" ]; then
			echo "No updates ($tcount/$icount).  Next check in: $psleep seconds"
		else
			echo ""
			echo "There are $tcount active threads with $icount address ranges"
			echo "Last 5 log entries:"
			$tapath -n 5 $asn/$asn-results.txt | $sepath 's/^/  /'
			echo "Scan progress: $progress% complete"
			echo "Next check in: $psleep seconds"
			echo ""
		fi
		sleep $psleep
	done
 	sdate=$($dapath)
	echo ""
	echo Scan completed on: $sdate
}

function asn_lookup {
	mkdir $asn > /dev/null 2>&1
	echo Looking up $asn
	asnname=$($bgpath asn -q $asn | $cupath -f 3 -d,)
	echo Searching for downstreams...
	$bgpath downstreams -q $asn
	echo ""
	echo $asn is listed as $asnname
	echo Based on the information above, please enter the downstream filtering keyword:
	read asnkeyword
	echo ""
	echo [Building ASN list]
	echo $asn > $asn/$asn-asnlist.txt
	$bgpath downstreams -q $asn | $grpath $asnkeyword | $cupath -f 1 -d, >> $asn/$asn-asnlist.txt
	echo ""
	echo [Building IP list]
	while read line; do
		echo Looking up ASN: $line
		$wipath -h whois.radb.net -- -i origin $line | $grpath -Eo "([0-9.]+){4}/[0-9]+" >> $asn/$asn-iplist.1
	done < $asn/$asn-asnlist.txt
	echo [Sorting and Removing Duplicates]
	$capath $asn/$asn-iplist.1 | $sopath | $unpath | $grpath -x '.\{10,30\}' > $asn/$asn-iplist.2
	rm -rf $asn/$asn-iplist.1
	echo [Consolidating ranges]
	$ncpath -f $asn/$asn-iplist.2 > $asn/$asn-iplist.txt
	rm -rf $asn/$asn-iplist.2
	listlength=$($capath $asn/$asn-iplist.txt | $wcpath -l)
	if [ "$listlength" -lt "2" ]; then
		echo "ERROR: Only $listlength Network Ranges were found! (min required: 2)"
		mv $asn/$asn-asnlist.txt ./$asn-asnlist.txt
		mv $asn/$asn-iplist.txt ./$asn-iplist.txt
		rm -rf $asn
		echo The ASN and IP list have been saved to: $asn-asnlist.txt and $asn-iplist.txt
		exit 1
	fi
	echo ""
	echo $listlength Network Ranges Found
}

# banner
echo "    __ _ ___ _ __  ___  ___ __ _ _ __"
echo "   / _\` / __| '_ \/ __|/ __/ _\` | '_ \ "
echo "  | (_| \__ \ | | \__ \ (_| (_| | | | |"
echo "   \__,_|___/_| |_|___/\___\__,_|_| |_|"
echo "    v1.0         Scan all the things.."
echo ""
echo ""


# resume scanning
if [ "$scantype" = "resume" ]; then
	if [ ! -f $asn/$asn-iplist.txt ]; then
		echo "ERROR: Data for a previous scan of $asn was not found."
		echo ""
		echo ""
		echo ""
		exit 1
	fi
  	resultscount=$($capath $asn/$asn-results.txt | $wcpath -l)
	if [ "$resultscount" = "0" ];then
		resumesort=0
	fi
	if [ "$resumesort" = "0" ]; then
		echo "No prior results were found!"
		echo ""
	else
		echo [Sorting and Filtering]
		fdate=$($dapath +%d%m%y%H%M%S)
		$capath $asn/$asn-results.txt | $grpath Scanning | $cupath -f 2 -d " " | $sopath > $asn/filterlist
		$capath $asn/$asn-iplist.txt | $sopath > $asn/iplist
		mv $asn/$asn-iplist.txt $asn/$asn-iplist-$fdate.txt.old
		$copath -13 $asn/filterlist $asn/iplist > $asn/$asn-iplist.txt
		rm -rf $asn/filterlist $asn/iplist
	fi
	echo [Consolidating Ranges]
	mv $asn/$asn-iplist.txt $asn/$asn-iplist.1
	$ncpath -f $asn/$asn-iplist.1 > $asn/$asn-iplist.txt
	rm -rf $asn/$asn-iplist.1
	listlength=$($capath $asn/$asn-iplist.txt | $wcpath -l)
	if [ "$listlength" -lt "2" ]; then
  	echo "ERROR: Only $listlength Network Ranges were found! (min required: 2)"
		exit 1
	fi
	echo ""
	echo $listlength Network Ranges Found
	read -p "Start scan (y/n)?" -n 1 -r
	echo ""
	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		echo  Updated IP list: $asn/$asn-iplist.txt
		echo Original IP list: $asn/$asn-iplist-$fdate.txt.old
		exit 0
	fi
	echo ""
	echo "Please enter the scan type (ie: curl):"
	read scantype
	if [ "$scantype" = "curl" ] || [ "$scantype" = "nmap" ]; then
		do_scan
	else
		echo "Invalid scan type.  Valid options are 'curl' or 'nmap' (in lower case)"
		echo ""
		echo "Last chance - Please enter the scan type (ie: curl):"
		read scantype
		if [ "$scantype" = "curl" ] || [ "$scantype" = "nmap" ]; then
			do_scan
		else
			echo Invalid scan type.  Aborting!
			echo ""
			echo  Updated IP list: $asn/$asn-iplist.txt
			echo Original IP list: $asn/$asn-iplist-$fdate.txt.old
			exit 0
		fi
	fi
	exit 0
fi

# manual scan (no asn lookups)
if [ "$scantype" = "manual" ]; then
	if [ ! -f $asn ]; then
		echo "ERROR: $asn was not found."
		echo ""
		echo ""
		echo ""
		exit 1
	fi
	mkdir $asn-manual > /dev/null 2>&1
	$capath $asn | $sopath > $asn-manual/$asn-manual-iplist.1
	echo [Consolidating Ranges]
	$ncpath -f $asn-manual/$asn-manual-iplist.1 > $asn-manual/$asn-manual-iplist.txt
	rm -rf $asn-manual/$asn-manual-iplist.1
	listlength=$($capath $asn-manual/$asn-manual-iplist.txt | $wcpath -l)
	if [ "$listlength" -lt "2" ]; then
		echo "ERROR: $listlength network ranges found! (minimum required: 2)"
		rm -rf $asn-manual
		exit 1
  	fi
	echo ""
	echo $listlength Network Ranges Found
	read -p "Start scan (y/n)?" -n 1 -r
	echo ""
	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		mv $asn-manual/$asn-manual-iplist.txt $asn-manual-iplist.txt
		rm -rf $asn-manual
		echo Consolidated IP list has been stored as $asn-manual-iplist.txt
		exit 0
	fi
	echo ""
	echo "Please enter the scan type (ie: curl):"
	read scantype
	asntemp=$asn
	export asn=$asntemp-manual
	do_scan
  exit 0
fi

# If scantype is not resume or manual, pass 'scantype' to asnworker as entered
asn_lookup
read -p "Start scan (y/n)?" -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
	mv $asn/$asn-asnlist.txt ./$asn-asnlist.txt
	mv $asn/$asn-iplist.txt ./$asn-iplist.txt
	rm -rf $asn
	echo The ASN and IP list have been saved to: $asn-asnlist.txt and $asn-iplist.txt
	exit 0
fi
do_scan
exit 0
