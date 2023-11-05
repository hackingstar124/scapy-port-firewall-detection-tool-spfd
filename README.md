# scapy-port-firewall-detection-tool-sspfd
In this script you can detect firewall in different ports of a website.It will work like this  
Running method 1
python '/home/kali/Desktop/spfd.py' -t ip address -p 3306 
Running method 2
python spfd.py -t ip address -p 80
Ouutput 
[WARNING] Firewall is stateless
[INFO] Port 3306 is filtered
[WARNING] Firewall is blocking on port 3306
[ERROR] Firewall detected on target ip address
[ERROR] Firewall type: stateless, block-based
if there was any firewall.The script will show different outputs according to the port that you provided.
you need to download those libraties in your system if you dont have 
1 scapy
2 argpurse 
3.logging 
