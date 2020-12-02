import time
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11
import pandas as pd
import hashlib

deviceList = []
dFrame = []
epoch = time.time() + 60   #set a fixed epoch length for detection

#Algorithm variables
k = 3
charsToKeep = 2
identifierCol = 'MAC address'
colB = 'MAC address'

###################Package sniffing function###################
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4:
            if pkt.addr2 not in deviceList:
                deviceList.append(pkt.addr2)
                #print("SSID: %s MAC addr: %s " %(pkt.info, pkt.addr2))
                dFrame.append(pkt.addr2)

###################Algorithm functions###################
def dataPreProcessing(targetColumn):
    # Performing data pseudonym (sha256 hash) and data truncation. Last 16 bits are kept.
    df[targetColumn] = df[targetColumn].apply(lambda x: hashlib.sha256(x.encode('utf-8')).hexdigest())
    df[targetColumn] = df[targetColumn].str.slice(-charsToKeep)
    df.to_csv('hashNtrunc.csv')  # optional output of hashed and truncated dataset for testing


def anonymityCheck(idColumn):
    # Check whehter dataset conforms to K anonymity
    low_freq = df[idColumn].isin(df[idColumn].value_counts()[df[idColumn].value_counts() < k].index)
    print(low_freq)
    return low_freq


def dataCorrection(columnB, low_freq, breakingKLen):
    #Keep 1/k of the rows which break K anonymity and sort them in ascending order
    #Using the idea of slicing dataframe.
    print('k value in dataCorrection is:' + str(k))
    if k==0:
        print('''k can't be set to 0. Please rest the k value''')
        exit(1)
    elif breakingKLen / k < 1:
        savedDataItems = df[low_freq].sort_values(by=[columnB]).head(1)                    #Case when the rows to keep is less than 1. Keeping 1 row
    else:
        savedDataItems = df[low_freq].sort_values(by=[columnB])[0:int(breakingKLen / k)]   #Case when rows to keep > 1. Slice the dataset from row 0 to the index of breakingKlen/k
    savedDataItems.drop_duplicates()                                                                #Remove potential duplicated rows from the rows to keep
    savedDataItems.to_csv('candidToKeep.csv')                                                       #Optional output for checking 'rows to keep'
    return savedDataItems

def dataReplication(candidRows):
    # Repeating the K-anonymity breaking rows by K times
    repeated = pd.concat([candidRows] * k, ignore_index=True)
    print('k value in dataReplicaiton is:' + str(k))
    print('length of repeated is ' + str(len(repeated)))
    return repeated


def finalOutput(datasetMain, datasetCorrection):
    # Concatenate the first two layers' outcome with the corrected dataset
    frames = [datasetMain, datasetCorrection]                                                       #The final processed dataset = Data which confirms to K-Anonymity + Processed K-anonymity breaking rows
    PDSE = pd.concat(frames)
    PDSE.to_csv('PDSE2.csv')
    print('k here is: ' + str(k))
    print('length of PDSE is ' + str(len(PDSE)))
    print('SUM of cleanedMainSet + repeated is ' + str(len(datasetMain) + len(datasetCorrection)))

def main():
    print('k is now set to: ' + str(k))
    dataPreProcessing(identifierCol)
    kBreakingRows = anonymityCheck(identifierCol)
    kBreakingLen = len(df[kBreakingRows].index)
    print('The length of rows breaking K anonymity is: ' + str(kBreakingRows))
    candidToKeep = dataCorrection(colB, kBreakingRows, kBreakingLen)
    breakingToKeep = dataReplication(candidToKeep)
    cleanedMainSet = df.groupby(identifierCol).filter(lambda x: len(x) >= k)
    print('length of dataset without K breaking rows is ' + str(len(cleanedMainSet)))
    finalOutput(cleanedMainSet, breakingToKeep)

####################Data anonymization on the fly###################
while time.time() <= epoch:
    sniff(iface="wlan0", prn=PacketHandler)
    df = pd.DataFrame(dFrame, columns=['MAC address'])
    concatList = []
    concatList.append(df)
    dfSum = pd.concat(concatList)
    df = dfSum
    main()

