import zmq
import pandas_zmq
import pandas as pd
import hashlib

context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://localhost:5555")
socket.setsockopt(zmq.SUBSCRIBE, ''.encode('utf-8'))
df = pandas_zmq.recv_dataframe(socket)

k = 3
charsToKeep = 2
identifierCol = 'MAC address'

def dataPreProcessing(targetColumn):
    # Performing data pseudonym (sha256 hash) and data truncation. Last n bits are kept.
    df[targetColumn] = df[targetColumn].apply(lambda x: hashlib.sha256(x.encode('utf-8')).hexdigest())
    df[targetColumn] = df[targetColumn].str.slice(-charsToKeep)
    df.to_csv('hashNtrunc.csv')  # optional output of hashed and truncated dataset for testing


def anonymityCheck(idColumn):
    # Check whehter dataset conforms to K anonymity
    low_freq = df[idColumn].isin(df[idColumn].value_counts()[df[idColumn].value_counts() < k].index)
    print(low_freq)
    return low_freq


def dataCorrection(low_freq, breakingKLen):
    #Keep 1/k of the rows which break K anonymity and sort them in ascending order
    #Using the idea of slicing dataframe.
    if k==0:
        print('''k can't be set to 0. Please rest the k value''')
        exit(1)
    elif breakingKLen / k < 1:
        savedDataItems = df[low_freq].sort_values(by=[low_freq]).head(1)
    else:
        savedDataItems = df[low_freq].sort_values(by=[low_freq])[0:int(breakingKLen / k)]
    savedDataItems.drop_duplicates()
    savedDataItems.to_csv('candidToKeep.csv') #optional output for checking results
    return savedDataItems

def dataReplication(candidRows):
    # Repeating the K-anonymity breaking rows by K times
    repeated = pd.concat([candidRows] * k, ignore_index=True)
    print('length of repeated is ' + str(len(repeated)))
    return repeated


def finalOutput(datasetMain, datasetCorrection):
    # Concatenate the first two layers' outcome with the corrected dataset
    frames = [datasetMain, datasetCorrection]
    PDSE = pd.concat(frames)
    PDSE.to_csv('PDSE2.csv')
    print('length of PDSE is ' + str(len(PDSE)))
    print('SUM of cleanedMainSet + repeated is ' + str(len(datasetMain) + len(datasetCorrection)))


def main():
    dataPreProcessing(identifierCol)
    kBreakingRows = anonymityCheck(identifierCol)
    kBreakingLen = len(df[kBreakingRows].index)
    print('The length of rows breaking K anonymity is: ' + str(kBreakingRows))
    candidToKeep = dataCorrection(kBreakingRows, kBreakingLen)
    breakingToKeep = dataReplication(candidToKeep)
    cleanedMainSet = df.groupby(identifierCol).filter(lambda x: len(x) >= k)
    print('length of dataset without K breaking rows is ' + str(len(cleanedMainSet)))
    finalOutput(cleanedMainSet, breakingToKeep)


while True:
    main()

