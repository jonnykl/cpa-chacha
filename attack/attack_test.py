#!/usr/bin/env python3


# Attacks multiple sets of traces and checks if the guessed key is correct.
# After completing all attacks the number of failed, successful and in the first
# run successful attacks are printed. Also the filenames of the failed attacks
# are printed.
# In the first run only the best subkeys are used. If this fails, a second
# attack will be performed where - wherever possible - two subkeys are
# calculated from which the better one gets selected.
# Filenames ending with .n1fixed.npz, .n2fixed.npz or .n12fixed.npz are ignored.
# This makes it possible to simply pass "traces/*" for TRACES_NPZ.
# For the other parameters see attack.py


from common import *
from chacha import *
from attack import attack_key, attack_key_reduced_controllable_input

from tqdm import tqdm, trange
import sys
import argparse
import multiprocessing as mp



def main():
    # parse args

    parser = argparse.ArgumentParser(description="Test attack parameters (subkey_samples.py)")

    parser.add_argument("TRACES_NPZ", nargs="+", help="set of traces")
    parser.add_argument("-x", "--pool-size", type=int, help="size of the multiprocessing pool")
    parser.add_argument("-r", "--reduced-controllable-input", action="store_true", help="counter and nonce[0] are fixed")
    parser.add_argument("-s", "--max-corr-per-sample", action="store_true", help="select best subkey by max correlation per sample")

    args = parser.parse_args()


    # filter out files ending with .n(1|2|12)fixed.npz
    filenames_traces = filter(lambda filename: not (filename.endswith(".n1fixed.npz") or filename.endswith(".n2fixed.npz") or filename.endswith(".n12fixed.npz")), args.TRACES_NPZ)


    pass_cnt = 0
    pass_first_try_cnt = 0
    fail_cnt = 0

    failed_filenames = []

    with mp.Pool(args.pool_size) as p:
        # process multiple files concurrently and show progress
        for filename, success, success_first_try in tqdm(p.imap(process_file, [(filename, args) for filename in filenames_traces]), total=len(args.TRACES_NPZ), desc="progress"):
            pass_cnt += success
            pass_first_try_cnt += success_first_try
            fail_cnt += not success

            if not success:
                failed_filenames.append(filename)

    print("pass/pass_first_try/fail/total: %d/%d/%d/%d" % (pass_cnt, pass_first_try_cnt, fail_cnt, pass_cnt+fail_cnt))

    print()
    print("failed filenames:")
    for filename in failed_filenames:
        print(filename)




def process_file(x):
    filename, args = x


    # load traces and associated input data

    trace_array, counter_array, nonce_array, correct_key = load_traces(filename)
    if correct_key is None:
        return False

    if args.reduced_controllable_input:
        trace_n1fixed_array, _, nonce_n1fixed_array, _ = load_traces(filename + ".n1fixed.npz")


    # perform the attack

    if not args.reduced_controllable_input:
        key = attack_key(trace_array, counter_array, nonce_array, args.max_corr_per_sample, two_best_subkeys=False, show_progress=False)
    else:
        key, _ = attack_key_reduced_controllable_input(trace_array, trace_n1fixed_array, counter_array, nonce_array, nonce_n1fixed_array, args.max_corr_per_sample, two_best_subkeys=False, show_progress=False)


    # check if the guessed key is correct

    guessed_correctly = True
    guessed_correctly_first_try = True
    for i, subkey in enumerate(key):
        correct_subkey = extract_subkey(correct_key, i)
        if subkey != correct_subkey:
            guessed_correctly = False
            guessed_correctly_first_try = False
            break

    if not guessed_correctly:
        # guessed key is not correct -> retry with two_best_subkeys=True

        if not args.reduced_controllable_input:
            key = attack_key(trace_array, counter_array, nonce_array, args.max_corr_per_sample, two_best_subkeys=True, show_progress=False)
        else:
            key, _ = attack_key_reduced_controllable_input(trace_array, trace_n1fixed_array, counter_array, nonce_array, nonce_n1fixed_array, args.max_corr_per_sample, two_best_subkeys=True, show_progress=False)

        guessed_correctly = True
        for i, subkey in enumerate(key):
            correct_subkey = extract_subkey(correct_key, i)
            if subkey != correct_subkey:
                guessed_correctly = False
                break

    return filename, guessed_correctly, guessed_correctly_first_try





if __name__ == "__main__":
    main()

