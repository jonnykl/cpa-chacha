#!/usr/bin/env python3


# Calculates TVLA for a given set of traces and plot the output. By default the
# TVLA is calculated for each step. It's possible to calculate the TVLA for each
# byte within each step and select the step/byte.


from common import *
from chacha import *

import numpy as np
import scipy as sp
import matplotlib.pyplot as plt
import sys
import argparse



def main():
    # parse agrs

    parser = argparse.ArgumentParser(description="Calculate and plot TVLA", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("TRACES_NPZ", help="set of traces")
    parser.add_argument("-b", "--subkey-bytes", action="store_true", help="calculate TVLA for every byte (instead of 32-bit word)")
    parser.add_argument("-s", "--step", type=int, help="number of step")
    parser.add_argument("-i", "--int-subkey", type=int, help="number of internal subkey")

    args = parser.parse_args()


    # load traces and associated input data

    trace_array, counter_array, nonce_array, correct_key = load_traces(args.TRACES_NPZ)


    # calculate TVLA and plot the output

    plt.title("TVLA")

    if not args.subkey_bytes:
        for step in range(16):
            if args.step is not None and step != args.step:
                continue

            testout = calc_tvla32(step, trace_array, counter_array, nonce_array, correct_key)
            plt.plot(testout, label=("%d" % step))
    else:
        for step in range(16):
            if args.step is not None and step != args.step:
                continue

            for int_subkey in range(4):
                if args.int_subkey is not None and int_subkey != args.int_subkey:
                    continue

                testout = calc_tvla8(step, int_subkey, trace_array, counter_array, nonce_array, correct_key)
                plt.plot(testout, label=("%d/%d" % (step, int_subkey)))

    num_points = trace_array.shape[1]
    plt.plot([-4.5]*num_points, color="black")
    plt.plot([4.5]*num_points, color="black")

    plt.legend()
    plt.show()


def calc_tvla32(step, trace_array, counter_array, nonce_array, correct_key):
    # group the traces
    groups = np.array([group32(step, counter_array[i], nonce_array[i], correct_key) for i in range(len(trace_array))])

    # calculate the TVLA using the welch's t-test
    return welch_ttest(trace_array, groups)


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




if __name__ == "__main__":
    main()

