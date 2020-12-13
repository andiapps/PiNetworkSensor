# PiNetworkSensor

INSTALLATION
------------
 * Install all framworks (using pip)
 * Put your wifi card to monitor mode 
 * Navigate to the folder where the script is 
 * Provide parameters in the following sequence: k, wifi card (in monitor mode) name
 * Run the script with your settings of the parameters

Latest update
------------
* Command line control has been updated. User has full control of following key parameters: K, Epoch length, Wifi card name, Desired number of epochs
* Timestamp for each row in the output
* Fully functioning in collecting network device MAC address, anonymize captured data on-the-fly and saving processed data to local storage

Current Problems
------------
 * A timer for auto starting and stopping the epoches is needed✅
 * The code generates 'memory error' after any epoch longer than 1 hour✅

To-do list
------------
 * Adding timer✅
 * Tests for epoches in different time length✅
 * Adding epoch length to command line parameter✅
