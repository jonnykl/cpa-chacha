#!/usr/bin/env python3


# Calculates TVLA for multiple sets of traces. The results are used to select
# samples with a high leakage. The relevant samples are saved as a python script
# named "subkey_samples.py". In this way it's possible to easily edit the
# samples manually afterwards.


from common import *
from chacha import *

import numpy as np
import scipy as sp
import sys
import argparse
import multiprocessing as mp



def main():
    # parse args

    parser = argparse.ArgumentParser(description="Calculate subkey samples from TVLA analyis")

    parser.add_argument("TRACES_NPZ", nargs="+", help="set of traces")
    parser.add_argument("-x", "--pool-size", type=int, help="size of the multiprocessing pool")

    args = parser.parse_args()


    # load traces

    trace_array, _, _, _ = load_traces(args.TRACES_NPZ[0])


    # score for each byte of each step

    total_score = np.zeros((16, 4, trace_array.shape[1]), dtype=np.int)


    with mp.Pool(args.pool_size) as p:
        # process multiple files concurrently and show progress
        for score in tqdm(p.imap(process_file, args.TRACES_NPZ), total=len(args.TRACES_NPZ), desc="progress"):
            total_score += score


    # sort values for each step/byte
    # save the five best samples (for each subkey byte)

    subkey_samples = np.argsort(total_score, axis=2)[:,:,::-1][:,:,:5]


    with open("subkey_samples.py", "w") as f_subkey_samples:
        f_subkey_samples.write("\nsubkey_samples = [\n")

        for step, step_samples in enumerate(subkey_samples):
            f_subkey_samples.write("    [\n")
            for int_subkey, int_subkey_samples in enumerate(step_samples):
                f_subkey_samples.write("        %s%s  # [%d,%d]\n" % (str(list(int_subkey_samples)), "," if int_subkey < 3 else " ", step, int_subkey))

            f_subkey_samples.write("    ]%s\n" % ("," if step < 15 else ""))

        f_subkey_samples.write("]\n\n")



def calc_tvla8(step, int_subkey, trace_array, counter_array, nonce_array, correct_key):
    # group the traces
    groups = np.array([group8(step, int_subkey, counter_array[i], nonce_array[i], correct_key) for i in range(len(trace_array))])

    # calculate the TVLA using the welch's t-test
    return welch_ttest(trace_array, groups)



# perform the welch's t-test
# returns zeros if all traces are in the same group
def welch_ttest(traces, group):
    traces_true = traces[group]
    traces_false = traces[~group]

    if len(traces_true) == 0 or len(traces_false) == 0:
        return [0]*traces.shape[1]

    ttrace = sp.stats.ttest_ind(traces_true, traces_false, axis=0, equal_var=False)[0]
    return np.nan_to_num(ttrace)



def process_file(filename):
    # load traces and associated input data

    trace_array, counter_array, nonce_array, correct_key = load_traces(filename)


    score = np.zeros((16, 4, trace_array.shape[1]), dtype=np.int)

    # calculate a score for each sample
    for step in range(16):
        for int_subkey in range(4):
            testout = calc_tvla8(step, int_subkey, trace_array, counter_array, nonce_array, correct_key)

            testout = np.abs(testout)
            best_samples = np.argsort(testout)[::-1]

            k = 20
            for j in range(k):
                # +k+1 for the sample with the highest t value
                # +k for the sample with the second highest t values
                # +k-1 for the sample with the third highest t values
                # ...

                score[step][int_subkey][best_samples[k-j-1]] += j+1

    return score




if __name__ == "__main__":
    main()

