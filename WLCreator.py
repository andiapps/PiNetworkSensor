import time
import datetime as dt
import sys
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11
from os import *
import collections
from collections import Counter
import pandas as pd
import numpy as np
import threading
import multiprocessing as mp

manager = mp.Manager()
allType2List = manager.list()           #list for saving white list MACs
bufferList = manager.list()             #Array for saving check list MACs
sem = threading.Semaphore()
#================================ Commandline parameters ========================================
parser = argparse.ArgumentParser(
    description="Please enter the wifi interface name(In monitor mode), epoch length(in seconds), white list length and desired number of runs")
parser.add_argument('iface', type=str, help='Monitor mode wifi card name')
#parser.add_argument('refEpoch', type=int, help='Length of reference epoch')
parser.add_argument('epoch', type=int, help='Length of each epoch')
parser.add_argument('wlepoch', type=int, help='length of white list collecting')
parser.add_argument('numOfEp', type=int, help='Desired number of runs')
args = parser.parse_args()

# Packet handler for storing white list
def PacketHandler(pkt):
    if pkt.haslayer(Dot11) and pkt.addr2 != None:
            allType2List.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
# Packet handler for storing check list
def BufferHandler(pkt):
    if pkt.haslayer(Dot11) and pkt.addr2 != None:
            bufferList.append((pkt.addr2, datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S')))
#================================ White and check list creating functions ===========================
def staticCreator():
    print('Running static')
    sniff(iface=args.iface, prn=PacketHandler, timeout=args.wlepoch)

def checkCreator(eps):
    for _ in range(eps):
        sem.acquire()
        print('==============Creating checklist=======')
        sniff(iface=args.iface, prn=BufferHandler, timeout=args.epoch)
        sem.release()
        #Give a tiny time gap to ensure the 'creating -> cleaning' sequence
        time.sleep(0.001)

#================Cleaner function for removing MACs haven't been detected for longer than 1 hour======
def checkCleaner(eps):
    for _ in range(eps):
            sem.acquire()
            sharedCheck = np.asarray(bufferList)
            dfCheckList = pd.DataFrame(sharedCheck)
            dfCheckList.columns = ['MAC', 'TIME']
            dfCheckList['TIME'] = dfCheckList['TIME'].apply(pd.to_datetime)
            dfCheckList.drop_duplicates('MAC', keep='last', inplace=True)
            print('=========Running Cleaning process=======')
            dfCheckList['diff'] = (pd.Timestamp.now().normalize() - dfCheckList['TIME']).abs().dt.total_seconds() / 60.0
            #Remove MACs which haven't been detected for more than 1 hour
            dfCheckList.drop( dfCheckList[dfCheckList['diff'] > 3600 ].index, inplace=True)
            dfCheckList.to_csv('cleanedList.csv', encoding='utf-8', index=True)
            sem.release()
            #Give a tiny time gap to ensure the 'creating -> cleaning' sequence
            time.sleep(0.001)

# Creating static list at the same time as creating checklist
p1 = mp.Process(target=staticCreator)
p1.start()
p1.join()
sharedArr = np.asarray(allType2List)
#Processing white list with pandas
dfWhiteList = pd.DataFrame(sharedArr)
dfWhiteList.columns = ['MAC', 'TIME']
dfWhiteList['TIME'] = dfWhiteList['TIME'].apply(pd.to_datetime)
dfWhiteList.drop_duplicates('MAC', keep='last', inplace=True)
dfWhiteList.to_csv('whiteList.csv', encoding='utf-8', index=True)

#Creating checklist while running cleaning function at the same time
eps = args.numOfEp
creator = threading.Thread(target=checkCreator, args=(eps,))
cleaner = threading.Thread(target=checkCleaner, args=(eps,))
creator.start()
cleaner.start()
creator.join()
cleaner.join()

#Update the white list at the end
dfCleanedCL = pd.read_csv('cleanedList.csv')
finalWhiteList = dfWhiteList[dfWhiteList.MAC.isin(dfCleanedCL.MAC)]
finalWhiteList.to_csv('finalOutput.csv', encoding='utf-8', index=True ) 
