#!/usr/bin/env python3


# Plots the raw power trace. By default the first trace of the set is plotted.
# It's possible to plot multiple traces and select the first/last sample.


from common import *

import numpy as np
import matplotlib.pyplot as plt
import sys
import argparse



def main():
    # parse args

    parser = argparse.ArgumentParser(description="Plot raw power trace", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("TRACES_NPZ", help="set of traces")
    parser.add_argument("-n", "--num-traces", type=int, default=1, help="max number of traces to plot")
    parser.add_argument("-s", "--start", type=int, help="first sample")
    parser.add_argument("-e", "--end", type=int, help="last sample")

    args = parser.parse_args()


    # load traces

    trace_array, _, _, _ = load_traces(args.TRACES_NPZ)


    start = args.start
    end = args.end

    if start is None:
        start = 0

    if end is None:
        end = trace_array.shape[1]

    
    trace_array = trace_array[:,start:end]


    # plot traces

    for trace in trace_array[:args.num_traces]:
        plt.plot(range(start, end), trace)

    plt.show()




if __name__ == "__main__":
    main()

