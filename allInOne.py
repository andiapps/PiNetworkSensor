import time
import sys
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11
import pandas as pd
import hashlib

deviceList = []
dFrame = []
epoch = time.time() + 5   #set a fixed epoch length for detection

parser = argparse.ArgumentParser(description = "Please enter the parameters for K and monitor mode wifi card's name")
parser.add_argument('k', type = int, help='Value of K for K-Anonymity algorithm')
parser.add_argument('iface', type=str, help='monitor mode wifi card name')
args = parser.parse_args()

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
    # Performing data pseudonym (sha256) and data truncation. Last 3 bits are kept.
    df[targetColumn] = df[targetColumn].apply(lambda x: bin(int(hashlib.sha256(x.encode()).hexdigest(), 16)&3).zfill(10))
    df.to_csv('hashNtrunc.csv')  # optional output of hashed and truncated dataset for testing


def anonymityCheck(idColumn):
    # Check whehter dataset conforms to K anonymity
    low_freq = df[idColumn].isin(df[idColumn].value_counts()[df[idColumn].value_counts() < args.k].index)
    print(low_freq)
    return low_freq


def dataCorrection(columnB, low_freq, breakingKLen):
    #Keep 1/k of the rows which break K anonymity and sort them in ascending order
    #Using the idea of slicing dataframe.
    print('k value in dataCorrection is:' + str(args.k))
    if args.k==0:
        print('''k can't be set to 0. Please rest the k value''')
        exit(1)
    elif breakingKLen / args.k < 1:
        savedDataItems = df[low_freq].sort_values(by=[columnB]).head(1)                    #Case when the rows to keep is less than 1. Keeping 1 row
    else:
        savedDataItems = df[low_freq].sort_values(by=[columnB])[0:int(breakingKLen / args.k)]   #Case when rows to keep > 1. Slice the dataset from row 0 to the index of breakingKlen/k
    savedDataItems.drop_duplicates()                                                                #Remove potential duplicated rows from the rows to keep
    savedDataItems.to_csv('candidToKeep.csv')                                                       #Optional output for checking 'rows to keep'
    return savedDataItems

def dataReplication(candidRows):
    # Repeating the K-anonymity breaking rows by K times
    repeated = pd.concat([candidRows] * args.k, ignore_index=True)
    print('k value in dataReplicaiton is:' + str(args.k))
    print('length of repeated is ' + str(len(repeated)))
    return repeated


def finalOutput(datasetMain, datasetCorrection):
    # Concatenate the first two layers' outcome with the corrected dataset
    frames = [datasetMain, datasetCorrection]                                                       #The final processed dataset = Data which confirms to K-Anonymity + Processed K-anonymity breaking rows
    PDSE = pd.concat(frames)
    PDSE.to_csv('pdseOutput.csv')
    print('length of PDSE is ' + str(len(PDSE)))
    print('SUM of cleanedMainSet + repeated is ' + str(len(datasetMain) + len(datasetCorrection)))

def main():
    print('k is now set to: ' + str(args.k))
    dataPreProcessing(identifierCol)
    kBreakingRows = anonymityCheck(identifierCol)
    kBreakingLen = len(df[kBreakingRows].index)
    print('The length of rows breaking K anonymity is: ' + str(kBreakingRows))
    candidToKeep = dataCorrection(colB, kBreakingRows, kBreakingLen)
    breakingToKeep = dataReplication(candidToKeep)
    cleanedMainSet = df.groupby(identifierCol).filter(lambda x: len(x) >= args.k)
    print('length of dataset without K breaking rows is ' + str(len(cleanedMainSet)))
    finalOutput(cleanedMainSet, breakingToKeep)

####################Data anonymization on the fly###################

sniff(iface = args.iface, prn=PacketHandler)
df = pd.DataFrame(dFrame, columns=['MAC address'])
concatList = []
concatList.append(df)
dfSum = pd.concat(concatList)
df = dfSum
main()
