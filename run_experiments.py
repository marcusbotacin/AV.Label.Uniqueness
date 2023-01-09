# Associates AV labels with AV engines
# Author: Marcus Botacin - TAMU - 2022
# Import Block
import sys
import os
import json
import numpy as np
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier as Classifier
import pickle
import random

# Wrapper class for learning stuff
class Model():
    def __init__(self):
        # Classifier (Random Forest)
        self.classifier = Classifier()
        # Encoders (String to int)
        # One for AV labels (X) and other for AV names (Y)
        self.encX = OneHotEncoder(handle_unknown='ignore', sparse=False)
        self.encY = OneHotEncoder(handle_unknown='ignore', sparse=False)

    # Training the model to associate AV and labels
    def train(self,train_set_X, train_set_Y):
        # First, encode the AV labels
        # Fit to create vocabulary
        av_labels_enc = self.encX.fit(np.array(train_set_X))
        # Then convert each word to an int vector
        transformed_X = []
        for av_label in train_set_X:
            transformed_X.append(self.encX.transform([av_label])[0])
        # Do the same for AV names
        av_names_enc = self.encY.fit(np.array(train_set_Y))
        transformed_Y = []
        for av_name in train_set_Y:
            transformed_Y.append(self.encY.transform([av_name])[0])
        # If numpy array, easier to handle
        self.X = np.array(transformed_X,dtype=np.float16)
        del av_labels_enc
        del transformed_X
        self.Y = np.array(transformed_Y,dtype=np.float16)
        del av_names_enc
        del transformed_Y
        # Actually fit the RF classifier
        self.classifier.fit(self.X,self.Y)

    # Given a label (string) returns an AV name (string)
    def predict(self,label):
        # first, convert label to embedding/encoding
        test_X = self.encX.transform([label])
        # Predict the encoding, will return another encoding
        out = self.classifier.predict(test_X)
        # convert resulting encode into av name string
        av = self.encY.inverse_transform(out)
        return av

# Auxiliary functions
# Read a file, straightforward
def read_file(filename):
    return open(filename,'r').read().strip().split("\n")

# Tokenize labels
def normalize_label(label):
    # convert separators into spaces
    label = label.replace("."," ")
    label = label.replace("-"," ")
    label = label.replace("/"," ")
    label = label.replace(":"," ")
    # then split in spaces (tokenize)
    label = label.strip().split(" ")
    return label

# normalize label size
# to train, we need all labels to have the same size
# we add empty strings until matching the size
# assuming receiving a maximum size as difference
def normalize_label_size(label,size):
    # comput how many empty strings to add
    diff = size - len(label)
    # if need to add any
    if diff > 0:
        # add the padding strings
        label = label + [""] * diff
    return label
 
# Normalize a list of labels regarding tis size
def normalize_label_list(label_list,size):
    new_labels = list()
    # traverses the list
    for label in label_list:
        # convert each one using the above normalization function
        new_labels.append(normalize_label_size(label,size))
    # result is a list of normalized labels
    return new_labels

# Split dataset into training and test sets
# Could have used scikit-learning folding
# But I prefer to have more control, so reimplemented it
def split_dataset(labels,av_names):
    # mid should be an integer
    mid = round(len(av_names)/2)
    # split vectors in the middle
    train_set_Y = av_names[:mid]
    train_set_X = labels[:mid]
    test_set_Y = av_names[mid+1:]
    test_set_X = labels[mid+1:]
    # return half of each vector in separate vars
    return train_set_X, train_set_Y, test_set_X, test_set_Y

# Interpret file content as a json from virustotal
def json_from_file(file_content):
    # Ideally, should use json.loads
    # But some of our previously-stored files were in a crazy format
    # so, we are getting the last line of the report, that contain the VT json
    # Warning: do not use eval on random inputs, it is not safe
    try:
        return eval(file_content[-1])
    except:
        return {}

# Get AV names and labels from a huge JSON file
def get_labels(json_content):
    _av_names = []
    _av_labels = []
    # Traverse all scans in the JSON
    for av_name in json_content['scans']:
        # Get the AV detection result
        res = json_content['scans'][av_name]
        # If detected, save. otherwise, forget
        if res['detected']:
            _av_names.append(av_name)
            _av_labels.append(res['result'])
    # return the list of names and labels
    return _av_names, _av_labels

# Returns a normalized confusion matrix
# I could have used scikit, but once again, i'd like more control
# I'd like to reuse it form any experiments, thus changing data
# Currently, assuming that a list of actual AV and predict AV names is inputted
def confusion_matrix(pred_pairs):
    # AV names in X axis
    avs_pred = [x[0][0][0] for x in pred_pairs]
    # AV names in Y axis
    avs_truth = [x[1][0] for x in pred_pairs]
    # Must merge because X and Y might have different AV names (some names might not have been predicted)
    # Must get unique ones, because we do not want repeated rows
    # Must be a list, because we need to query index
    all_avs = list(set(avs_pred+avs_truth))
    # Create a squared matrix NxN with zeros, then we add data
    matrix = np.zeros(shape=(len(all_avs),len(all_avs)))
    print("Matrix is %dx%d" % (len(all_avs),len(all_avs)))
    if len(all_avs) < int(sys.argv[2]):
        print("Not enough samples")
        sys.exit(0)
    # for each pair 
    for x,y in pred_pairs:
        # Map AV name to list index
        idx_x = all_avs.index(x)
        # Map AV name to list index
        idx_y = all_avs.index(y[0])
        # Increment "shoot" in that position
        matrix[idx_x][idx_y] = matrix[idx_x][idx_y] + 1
    # normalization
    # sum all lines, then divide
    for line in range(len(all_avs)):
        # Every row sum starts as zero
        sum = 0
        # traverse all columns of that row, summing all
        for column in range(len(all_avs)):
            sum = sum + matrix[line][column]
        # Traverse once again, now dividing by the total
        for column in range(len(all_avs)):
            # ignore division by zero
            if sum != 0:
                matrix[line][column] = matrix[line][column] / float(sum)
    return matrix

if len(sys.argv)!=5:
    print("Usage: python script.py <list_of_files> <number_of_avs> <samples per run> <number_of_runs>")
    sys.exit(0)

N_AVS = int(sys.argv[2])
SAMPLES_PER_RUN = int(sys.argv[3])
NUMBER_OF_RUNS = int(sys.argv[4])
filename = "avs_%d_samples_%d_runs_%d.results" % (N_AVS,SAMPLES_PER_RUN,NUMBER_OF_RUNS)
# check if file already exists
if os.path.exists(filename):
    print("Already computed")
    sys.exit(0)

print("Reading input file list...")
files = read_file(sys.argv[1])
f = open('all_av_names.pkl','rb')
all_av_names = pickle.load(f)
f = open('all_data.pkl','rb')
all_data = pickle.load(f)

average = np.zeros(shape=(20,NUMBER_OF_RUNS))
for n_runs in range(NUMBER_OF_RUNS):
    print("RUN: %d" % n_runs)
    # Var Initialization
    max_size = 0
    av_names = []
    av_labels = []
    model = Model()
    target_avs = random.sample(list(all_av_names),N_AVS)
    print("Selected AVs: ",target_avs)
    # Read all files in the list
    for idx, data in enumerate(all_data):
        a = data[0]
        b = data[1]
        # for each pair
        for av_name, av_label in zip(a,b):
            if av_name in target_avs:
                # tokenize the label
                label = normalize_label(av_label)
                # compute maximum length for future normalization
                if len(label) > max_size:
                    max_size = len(label)
                if av_names.count([av_name]) < SAMPLES_PER_RUN:
	                av_names.append([av_name])
        	        av_labels.append(label)

    print("Creating train and test datasets...")
    # Normalize size
    new_labels = normalize_label_list(av_labels, max_size)
    # Split into train and test set if required (sometimes we just want to train)
    #train_set_X, train_set_Y, test_set_X, test_set_Y = split_dataset(new_labels,av_names)
    train_set_X = new_labels
    train_set_Y = av_names
    test_set_X = train_set_X
    test_set_Y = train_set_Y

    print("Train set size %d" % len(train_set_X))

    print("Training the classifier...")
    # train the ML model with the train set
    model.train(train_set_X,train_set_Y)

    print("Predicting...")
    pred_pairs = []
    # For every element in the test set
    for idx, _label_vector in enumerate(test_set_X):
        if idx % 5000 == 0:
            print("Predicting set: %d" % idx)

        # label will be tokenized, but here we need the label as string to reuse the code
        label = ' '.join(_label_vector).strip()
        # then we tokenize again
        # I used this untoken-token-untoken structure so I can handwrite any string here to test
        label = normalize_label(label)
        # and normalize size
        label = normalize_label_size(label,max_size)
        # Pass the label to the prediction, will return an AV name
        av = model.predict(label)
        #print(av, test_set_Y[idx])
        # save pairs to compute metrics (if required)
        pred_pairs.append([av, test_set_Y[idx]])

    print("Computing Metrics...")

    # Assuming metrics are required, get confusion matrix from the pairs
    CM = confusion_matrix(pred_pairs)
    for threshold in range(100,0,-5):
        n_acc =0 # number of correct matches
        # for all columns
        for i in range(len(CM)):
            # diagonal means correct
            if float(CM[i][i]) >= threshold/float(100):
                # account the number of AVs with 100% match with their labels
                n_acc+=1
                indice = int((100-threshold)/5)
                average[indice][n_runs] = n_acc
        print("Identify %d %d of %d AVs (%f)" % (threshold,n_acc,len(CM),100*n_acc/float(len(CM))))

f = open(filename,'w')
for lines in range(20):
    _sum = 0
    for cols in range(NUMBER_OF_RUNS):
        _sum = _sum + average[lines][cols]
    _mean = (_sum/float(NUMBER_OF_RUNS))/float(N_AVS)
    print("Identify on AVERAGE [THRESHOLD=%d]: %f" % (100-(5*lines),_mean))
    f.write("Identify on AVERAGE [THRESHOLD=%d]: %f\n" % (100-(5*lines),_mean))
