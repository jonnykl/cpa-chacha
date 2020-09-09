#!/usr/bin/env python3


# Capture sets of traces and save the recorded data together with the input
# data. It's possible to specify the number of sets, the number of traces per
# set and the number of samples per trace.
# By default 1000 sets of 500 traces with each 4000 samples with a fixed random
# key and random counter and nonce are recorded. When passing -r the counter and
# the first byte of the nonce are fixed to a random value. When passing -1 or -2
# the second/third word of the nonce are fixed to 0x55555555.
# When passing filenames of recorded traces, new traces with the same key and
# counter/nonce[0] (-r) are recorded and saved with the same filename to the
# current directory.


from common import *

from tqdm import tqdm, trange
import random
import sys
import os
import argparse


def main():
    # parse args

    parser = argparse.ArgumentParser(description="Capture sets of traces", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("TRACES_NPZ", nargs="*", help="set of traces")
    parser.add_argument("-s", "--num-sets", type=int, default=argparse.SUPPRESS, help="number of sets (default: 1000)")
    parser.add_argument("-t", "--num-traces", type=int, default=500, help="number of traces per set")
    parser.add_argument("-n", "--num-samples", type=int, default=4000, help="number of samples per trace")
    parser.add_argument("-r", "--reduced-controllable-input", action="store_true", help="counter and nonce[0] are fixed")
    parser.add_argument("-1", "--nonce-1-fixed", action="store_true", help="nonce[1] fixed to 0x55555555")
    parser.add_argument("-2", "--nonce-2-fixed", action="store_true", help="nonce[2] fixed to 0x55555555")

    args = parser.parse_args()


    # check args

    if len(args.TRACES_NPZ) == 0:
        if "num_sets" not in args:
            args.num_sets = 1000
    else:
        if "num_sets" in args:
            parser.error("number of traces and file(s) specified ")


    # init scope and target

    scope, target, _ = init_scope()

    scope.adc.samples = args.num_samples
    target.output_len = 0


    # sometimes the ADC doesn't get locked which would lead to wrong measurements

    if not scope.clock.adc_locked:
        print("error: adc not locked")
        sys.exit(1)


    num_sets = len(args.TRACES_NPZ)
    if num_sets == 0:
        num_sets = args.num_sets
    
    print("capturing %d sets of %d traces (total: %d) ..." % (num_sets, args.num_traces, num_sets*args.num_traces))


    # capture traces

    for i in trange(num_sets, desc="set"):
        if len(args.TRACES_NPZ) > 0:
            filename = args.TRACES_NPZ[i]
            _, counter_array, nonce_array, key = load_traces(filename)

            key = bytearray(key)
            counter = bytearray(counter_array[0])
            nonce0 = bytearray(nonce_array[0][0:4])
        else:
            filename = "traces_%d.npz" % i

            # generate new key/counter/nonce[0] for each set

            key = bytearray(32)
            for j in range(len(key)):
                key[j] = random.randint(0, 255)

            if args.reduced_controllable_input:
                counter = bytearray(4)
                for j in range(len(counter)):
                    counter[j] = random.randint(0, 255)

                nonce0 = bytearray(4)
                for j in range(len(nonce0)):
                    nonce0[j] = random.randint(0, 255)
            else:
                counter = None
                nonce0 = None


        trace_array, counter_array, nonce_array = capture_trace_set(scope, target, args.num_traces, key, counter, nonce0, args.nonce_1_fixed, args.nonce_2_fixed)
        known_key = np.asarray(key)


        # save data

        filename_ext = ""
        if args.nonce_1_fixed and args.nonce_2_fixed:
            filename_ext = ".n12fixed.npz"
        elif args.nonce_1_fixed:
            filename_ext = ".n1fixed.npz"
        elif args.nonce_2_fixed:
            filename_ext = ".n2fixed.npz"

        np.savez_compressed(os.path.basename(filename) + filename_ext,
            trace_array=trace_array,
            counter_array=counter_array,
            nonce_array=nonce_array,
            known_key=known_key)


    print("... done!")



def capture_trace_set(scope, target, num_traces, key, counter, nonce0, n1fixed, n2fixed):
    counter_fixed = counter is not None
    nonce0_fixed = nonce0 is not None

    traces = []
    for _ in trange(num_traces, leave=False, desc="trace"):
        if not counter_fixed:
            # generate a new counter if not fixed

            counter = bytearray(4)
            for j in range(len(counter)):
                counter[j] = random.randint(0, 255)

        # send counter to the target

        target.simpleserial_write('c', counter)
        if target.simpleserial_wait_ack(timeout=250) is None:
            raise Warning("Device failed to ack")


        # generate a new nonce considering the parameters

        nonce = bytearray(12)
        for j in range(len(nonce)):
            if j < 4:
                if nonce0_fixed:
                    nonce[j] = nonce0[j]
                else:
                    nonce[j] = random.randint(0, 255)
            elif j < 8:
                if n1fixed:
                    nonce[j] = 0x55
                else:
                    nonce[j] = random.randint(0, 255)
            else:
                if n2fixed:
                    nonce[j] = 0x55
                else:
                    nonce[j] = random.randint(0, 255)

        # send nonce to the target

        target.simpleserial_write('n', nonce)
        if target.simpleserial_wait_ack(timeout=250) is None:
            raise Warning("Device failed to ack")


        # capture the trace

        trace = cw.capture_trace(scope, target, bytes(1), key)
        if trace is None:
            continue

        traces.append((trace, counter, nonce))


    trace_array = np.asarray([t[0].wave for t in traces])
    counter_array = np.asarray([t[1] for t in traces])
    nonce_array = np.asarray([t[2] for t in traces])

    return trace_array, counter_array, nonce_array




if __name__ == "__main__":
    main()

