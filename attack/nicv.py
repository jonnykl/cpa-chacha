#!/usr/bin/env python3


# Calculates NICV for a given set of traces and plot the output. By default the
# NICV is calculated for each step. It's possible to calculate the NICV for each
# byte within each step and select the step/byte.


from common import *
from chacha import *

import numpy as np
import matplotlib.pyplot as plt
import argparse



def main():
    # parse args

    parser = argparse.ArgumentParser(description="Calculate NICV and plot the output")

    parser.add_argument("TRACES_NPZ", help="set of traces")
    parser.add_argument("-b", "--subkey-bytes", action="store_true", help="calculate NICV for every byte (instead of 32-bit word)")
    parser.add_argument("-s", "--step", type=int, help="number of step")
    parser.add_argument("-i", "--int-subkey", type=int, help="number of internal subkey")

    args = parser.parse_args()


    # load traces and associated input data

    trace_array, counter_array, nonce_array, correct_key = load_traces(args.TRACES_NPZ)


    # calculate NICV and plot the output

    plt.title("NICV")

    if not args.subkey_bytes:
        for step in range(16):
            if args.step is not None and step != args.step:
                continue

            testout = calc_nicv32(step, trace_array, counter_array, nonce_array, correct_key)
            plt.plot(testout, label=("%d" % step))
    else:
        for step in range(16):
            if args.step is not None and step != args.step:
                continue

            for int_subkey in range(4):
                if args.int_subkey is not None and int_subkey != args.int_subkey:
                    continue

                testout = calc_nicv8(step, int_subkey, trace_array, counter_array, nonce_array, correct_key)
                plt.plot(testout, label=("%d/%d" % (step, int_subkey)))


    plt.legend()
    plt.show()


def calc_nicv32(step, trace_array, counter_array, nonce_array, correct_key):
    # group the traces
    groups = np.array([group32(step, counter_array[i], nonce_array[i], correct_key) for i in range(len(trace_array))])
    
    # calculate the NICV
    return nicv(trace_array, groups)


def calc_nicv8(step, int_subkey, trace_array, counter_array, nonce_array, correct_key):
    # group the traces
    groups = np.array([group8(step, int_subkey, counter_array[i], nonce_array[i], correct_key) for i in range(len(trace_array))])

    # calculate the NICV
    return nicv(trace_array, groups)


# calculates the NICV for a set of grouped traces
def nicv(traces, groups):
    all_groups = []
    for group in groups:
        if group not in all_groups:
            all_groups.append(group)

    traces_grouped = []
    for group in all_groups:
        traces_grouped.append(traces[groups == group])

    means = [np.mean(traces_group, axis=0) for traces_group in traces_grouped]

    variance_a = np.var(means, axis=0)
    variance_b = np.var(traces, axis=0)

    return variance_a/variance_b




if __name__ == "__main__":
    main()

