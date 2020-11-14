# PiNetworkSensor

INSTALLATION
------------
 * Install all framworks (using pip)
 * Put your wifi card to monitor mode 
 * Navigate to the folder where the script is
 * Use the follwoing format to run scanning (X = index number of your monitor mode enbaled wifi card): python sniffer03.py wlanX

Current Problems
------------
 * Header of the csv still reapeats every time new row is added 

To-do list
------------
 * Fix the header issue. Make it add header only once 
 * Run scanning every X minutes and give epoch counting to each scan
 * Output the result in csv format 
