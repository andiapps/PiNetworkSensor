# PiNetworkSensor

INSTALLATION
------------
 * Install all framworks (using pip)
 * Put your wifi card to monitor mode 
 * Navigate to the folder where the script is
 * Modify the wlan interface name at the bottom of server script to your wifi card (monitor mode). Run server and client code. 
 * The output will be saved as an external CSV file

Current Problems
------------
 * The code generates error sometime if the input doesn't contain any data (No captured data) 
 * Manually starting, stopping the code isn't ideal 
 * The code will stop running after receiving certain numbers of input data

To-do list
------------
 * Run scanning every X minutes and give epoch counting to each scan
 * Create an easier way to start and stop the code
