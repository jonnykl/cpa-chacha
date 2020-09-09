#!/usr/bin/env python3


# Attacks a set of traces trying to recover the key. By default it is assumed
# that the attacker has full control over all input data. The best samples are
# selected by the maximum correlation. It's possible to specify that the
# attacker can only control nonce[1] and nonce[2]. In this case the script
# expects a second set of traces with nonce[1] fixed to a constant value with
# the filename suffix ".n1fixed.npz". In both cases it's also possible two
# specify that the best sample should be selected by the maximum correlation per
# sample (candidate with the most samples having the maximum correlation) and
# that the two best subkeys should be considered. In this case the correlation
# of both 32-bit subkeys is calculated. This correlation is used to select te
# best subeky according to the other parameters.
# The script exits with the status code 0 if the key was successfully guessed
# or the key is not known (saved together with the traces), 3 otherwise.


from chacha import *
from common import *

from tqdm import tqdm, trange
import numpy as np
import matplotlib.pyplot as plt
import random
import struct
import sys
import argparse

try:
    from subkey_samples import *
except ImportError:
    print("error: could not find subkey_samples.py; it has to be generated before using this script")
    sys.exit(1)




def main():
    # parse args

    parser = argparse.ArgumentParser(description="Try to recover a ChaCha Key from traces")

    parser.add_argument("TRACES_NPZ", help="set of traces")
    parser.add_argument("-r", "--reduced-controllable-input", action="store_true", help="counter and nonce[0] are fixed")
    parser.add_argument("-s", "--max-corr-per-sample", action="store_true", help="select best subkey by max correlation per sample")
    parser.add_argument("-t", "--two-best-subkeys", action="store_true", help="also consider the second best subkeys guess (in the first half of the key)")
    parser.add_argument("-p", "--plot-corrs", action="store_true", help="plot the correlation of the best subkeys")
    parser.add_argument("-q", "--quiet", action="store_true", help="don't output anything")

    args = parser.parse_args()


    # load traces and associated input data

    trace_array, counter_array, nonce_array, correct_key = load_traces(args.TRACES_NPZ)

    if args.reduced_controllable_input:
        trace_n1fixed_array, _, nonce_n1fixed_array, _ = load_traces(args.TRACES_NPZ + ".n1fixed.npz")


    if not args.quiet:
        # print the correct_key and several intermediate states (if known)

        if correct_key is not None:
            print("correct key:")
            for i in range(8):
                print("%08x" % extract_subkey(correct_key, i))

            print()


            if args.reduced_controllable_input:
                counter0 = unpack_counter(counter_array[0])
                nonce_n1fixed0 = unpack_nonce(nonce_n1fixed_array[0])

                state0 = initial_state(key=[extract_subkey(correct_key, i) for i in range(8)], counter=counter0, nonce=nonce_n1fixed0)
                state1 = np.zeros((4, 4), dtype=np.int)
                for i in range(4):
                    state1[:,i] = quarter_round(*state0[:,i])

                print("v0'  = %08x" % state1[0,0])
                print("v4'  = %08x" % state1[1,0])
                print("v8'  = %08x" % state1[2,0])
                print("v12' = %08x" % state1[3,0])
                print("v1'  = %08x" % state1[0,1])
                print("v5'  = %08x" % state1[1,1])
                print("v9'  = %08x" % state1[2,1])
                print("v13' = %08x" % state1[3,1])
                print()

                a0 = state1[0,1]        # v1'
                b0 = state1[1,2]        # v6'
                d0 = state1[3,0]        # v12'
                a1 = ADD(a0, b0)
                d2 = ROTL(d0 ^ ADD(a0, b0), 16)
                print("a0   = %08x" % a0)
                print("d0   = %08x" % d0)
                print("a1   = %08x" % a1)
                print("d2   = %08x" % d2)
                print()

                a0 = state1[0,0]        # v0'
                b0 = state1[1,1]        # v5'
                a1 = ADD(a0, b0)
                print("a0   = %08x" % a0)
                print("a1   = %08x" % a1)
                print("b0   = %08x" % b0)
                print()


    # perform the attack

    if args.reduced_controllable_input:
        key, key_wrong = attack_key_reduced_controllable_input(trace_array, trace_n1fixed_array, counter_array, nonce_array, nonce_n1fixed_array, args.max_corr_per_sample, args.two_best_subkeys, not args.quiet, args.plot_corrs)
    else:
        key = attack_key(trace_array, counter_array, nonce_array, args.max_corr_per_sample, args.two_best_subkeys, not args.quiet, args.plot_corrs)
        key_wrong = False


    if not args.quiet:
        # print the results

        if correct_key is not None:
            print()

        if key_wrong:
            print("warning: guessed key is not correct (wrong internal state)")
            print()

        print("guessed key:")
        for subkey in key:
            print("%08x" % subkey)

        if correct_key is not None:
            print()
            print("wrong parts of the guessed key:")
            for ext_subkey, subkey in enumerate(key):
                for int_subkey, subkey_byte in enumerate(struct.pack(">I", subkey)):
                    if subkey_byte != correct_key[4*ext_subkey + (3-int_subkey)]:
                        print("%02x" % subkey_byte, end="")
                    else:
                        print("..", end="")

                print()


    if correct_key is not None:
        guessed_correctly = True
        for i, subkey in enumerate(key):
            correct_subkey = extract_subkey(correct_key, i)
            if subkey != correct_subkey:
                guessed_correctly = False
                break


        if not args.quiet:
            print()

            if guessed_correctly:
                print("key guessed correctly!")
            else:
                print("key NOT guessed correctly!")


        if not guessed_correctly:
            sys.exit(3)


    sys.exit(0)




# calculates the best subkeys by the maximum correlation
# corrs (num_subkeys, num_samples): contains lists of correlations for multiple subkeys
def select_best_subkey_by_max_corr(corrs):
    corrs_abs = np.abs(corrs)

    # calculate min/max/max_abs corrs for each subkey
    abs_max_corr_per_subkey = np.max(corrs_abs, axis=1)
    max_corr_per_subkey = np.max(corrs, axis=1)
    min_corr_per_subkey = np.min(corrs, axis=1)

    # sort the correlations: results are the sorted indexes of the subkeys
    best_subkeys_abs = np.argsort(abs_max_corr_per_subkey)[::-1]
    best_subkeys_pos = np.argsort(max_corr_per_subkey)[::-1]
    best_subkeys_neg = np.argsort(min_corr_per_subkey)

    # sort the correlations
    corrs_abs = corrs[best_subkeys_abs]
    corrs_pos = corrs[best_subkeys_pos]
    corrs_neg = corrs[best_subkeys_neg]

    return (best_subkeys_abs, best_subkeys_pos, best_subkeys_neg), (corrs_abs, corrs_pos, corrs_neg)


# calculates the best subkeys by the maximum correlation per sample
#
# The maximum correlation is calculated for each sample. So each sample has a
# subkey with the best correlation. The subkey which has the most often the best
# correlation is the best subkey.
#
# corrs (num_subkeys, num_samples): contains lists of correlations for multiple subkeys
def select_best_subkey_by_max_corr_per_sample(corrs):
    corrs_abs = np.abs(corrs)

    # counters for each subkey
    best_subkeys_abs_cnt = [0]*len(corrs)
    best_subkeys_pos_cnt = [0]*len(corrs)
    best_subkeys_neg_cnt = [0]*len(corrs)
    for i in range(corrs_abs.shape[1]):
        # calculate min/max/max_abs for each subkey and the current sample
        best_subkey_abs = np.argmax(corrs_abs[:,i])
        best_subkey_pos = np.argmax(corrs[:,i])
        best_subkey_neg = np.argmin(corrs[:,i])

        # increase each corresponding counter
        best_subkeys_abs_cnt[best_subkey_abs] += 1
        best_subkeys_pos_cnt[best_subkey_pos] += 1
        best_subkeys_neg_cnt[best_subkey_neg] += 1

    # sort the counters: results are the sorted indexes of the subkeys
    best_subkeys_abs = np.argsort(best_subkeys_abs_cnt)[::-1]
    best_subkeys_pos = np.argsort(best_subkeys_pos_cnt)[::-1]
    best_subkeys_neg = np.argsort(best_subkeys_neg_cnt)[::-1]

    # sort the correlations
    corrs_abs = corrs[best_subkeys_abs]
    corrs_pos = corrs[best_subkeys_pos]
    corrs_neg = corrs[best_subkeys_neg]

    return (best_subkeys_abs, best_subkeys_pos, best_subkeys_neg), (corrs_abs, corrs_pos, corrs_neg)


# creates two new arrays containing alternating positive and negative correlations (and corresponding subkeys)
def combine_pos_neg(pos_best_subkeys, neg_best_subkeys, pos_corrs, neg_corrs):
    best_subkeys = []
    corrs = []

    for pos_best_subkey, neg_best_subkey, pos_corrs2, neg_corrs2 in zip(pos_best_subkeys, neg_best_subkeys, pos_corrs, neg_corrs):
        best_subkeys.append(pos_best_subkey)
        best_subkeys.append(neg_best_subkey)

        corrs.append(pos_corrs2)
        corrs.append(neg_corrs2)

    return best_subkeys, corrs



# attack a single subkey byte
def attack_subkey(trace_array, counter_array, nonce_array, step, int_subkey, samples, state0, state1, subkey, max_corr_per_sample, comb_pos_neg, show_progress=False, plot_corrs=False):
    # calculate the correlations
    corrs = calc_corrs8(trace_array, counter_array, nonce_array, step, int_subkey, samples, state0, state1, subkey, show_progress)
    corrs = np.array(corrs)

    # select the best subkeys
    if not max_corr_per_sample:
        best_subkeys, corrs = select_best_subkey_by_max_corr(corrs)
    else:
        best_subkeys, corrs = select_best_subkey_by_max_corr_per_sample(corrs)

    if plot_corrs:
        # plot the correlations of the four best (highest absolute correlation) subkey bytes
        for i, x in enumerate(corrs[0][:4]):
            plt.plot(x, label=str("#%d/%02x" % (i, best_subkeys[0][i])))

        plt.legend()
        plt.show()

    if comb_pos_neg:
        # combine positive and negative correlations
        best_subkeys, corrs = combine_pos_neg(best_subkeys[1], best_subkeys[2], corrs[1], corrs[2])
    else:
        # only use the best subkeys / correlations based on the absolute correlations
        best_subkeys, corrs = best_subkeys[0], corrs[0]

    return best_subkeys, corrs



# attack a 32-bit subkey and use the best subkey
def attack_best_subkey(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, symmetric_model, progress, plot_corrs):
    subkey = 0
    for int_subkey in range(4):
        bit_pos = int_subkey*8

        # attack a single subkey byte
        subkey_bytes, _ = attack_subkey(trace_array, counter_array, nonce_array, step, int_subkey, subkey_samples[step][int_subkey], state0, state1, subkey, max_corr_per_sample, symmetric_model, progress is not None, plot_corrs)
        if progress is not None:
            progress.update()

        if symmetric_model:
            # use subkey with the best negative correlation
            subkey |= subkey_bytes[1]<<bit_pos
        else:
            # use subkey with the best absolute correlation
            subkey |= subkey_bytes[0]<<bit_pos

    state0 = np.copy(state0)
    state1 = np.copy(state1)

    # update the subkey in the corresponding state
    state01 = (state0, state1)
    state01[idx_subkey_by_step[step][0]][idx_subkey_by_step[step][1:3]] = subkey

    return state0, state1



# attack a 32-bit subkey: calculate the two best subkeys and then selects the best of the two subkeys
def attack_two_best_subkeys(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, symmetric_model, progress, plot_corrs, subkeys=None, int_subkey=0, offset=0):
    N = 2

    # end the recursion
    if int_subkey >= 4:
        return

    initial_call = subkeys is None
    if initial_call:
        # N**num_subkey_bytes = 2**4 = 16
        subkeys = np.zeros(N**4, dtype=np.int)

    # attack a single subkey byte
    subkey = subkeys[offset]
    best_subkeys, _ = attack_subkey(trace_array, counter_array, nonce_array, step, int_subkey, subkey_samples[step][int_subkey], state0, state1, subkey, max_corr_per_sample, symmetric_model, progress is not None, plot_corrs)
    if progress is not None:
        progress.update()

    bit_pos = int_subkey*8

    # length of the current segment of the subkeys
    l = len(subkeys)//(N**(int_subkey+1))

    for i in range(N):
        if symmetric_model:
            # use subkey with the best negative correlation
            best_subkey = best_subkeys[2*i+1]
        else:
            # use subkey with the best absolute correlation
            best_subkey = best_subkeys[i]

        subkeys[offset+i*l:offset+(i+1)*l] |= best_subkey<<bit_pos

    # recursivly call this function for the best calculated subkey bytes
    for i in range(N):
        attack_two_best_subkeys(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, symmetric_model, progress, plot_corrs, subkeys, int_subkey+1, offset+i*l)

    if initial_call:
        # select the best subkey
        subkey = select_n_best_subkeys(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, subkeys, 1)[0]

        state0 = np.copy(state0)
        state1 = np.copy(state1)

        # update the subkey in the corresponding state
        state01 = (state0, state1)
        state01[idx_subkey_by_step[step][0]][idx_subkey_by_step[step][1:3]] = subkey

        return state0, state1



# select the best n 32-bit subkeys based on the best correlation
def select_n_best_subkeys(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, subkeys, n):
    samples = np.unique(np.array(subkey_samples[step]).flatten())

    corrs = calc_corrs32(trace_array, counter_array, nonce_array, step, samples, state0, state1, subkeys)
    corrs = np.array(corrs)

    if not max_corr_per_sample:
        idx_best_subkeys = select_best_subkey_by_max_corr(corrs)[0][0]
    else:
        idx_best_subkeys = select_best_subkey_by_max_corr_per_sample(corrs)[0][0]

    best_subkeys = np.array(subkeys)[idx_best_subkeys]

    #if plot_corrs:
    if True:
        corrs = corrs[idx_best_subkeys]

        # plot the correlations of the four best (highest absolute correlation) subkey bytes
        for i, x in enumerate(corrs[:4]):
            plt.plot(x, label=str("#%d/%08x" % (i, best_subkeys[i])))

        plt.legend()
        plt.show()

    return best_subkeys[:n]




# attack a 32-bit subkey
def attack_subkey_word(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, two_best_subkeys, symmetric_model, progress, plot_corrs):
    if not two_best_subkeys:
        return attack_best_subkey(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, symmetric_model, progress, plot_corrs)
    else:
        return attack_two_best_subkeys(trace_array, counter_array, nonce_array, step, state0, state1, max_corr_per_sample, symmetric_model, progress, plot_corrs)



# attack the key assuming the counters and nonces are random
def attack_key(trace_array, counter_array, nonce_array, max_corr_per_sample, two_best_subkeys, show_progress=False, plot_corrs=False):
    if show_progress:
        if not two_best_subkeys:
            total = 8*4
        else:
            total = 8*15

        progress = tqdm(total=total, desc="progress")


    # init states

    state0 = initial_state()
    state1 = np.zeros((4, 4), dtype=np.int)


    # attack each 32-bit word

    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 0, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 1, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 2, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 3, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 4, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 5, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 6, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, _ = attack_subkey_word(trace_array, counter_array, nonce_array, 7, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)


    if show_progress:
        progress.close()


    # extract the key from the state

    key = list(state0[1:3].flatten())


    return key



# attack the key assuming the counter and nonce[0] are fixed and nonce[1:3] are random / fixed
def attack_key_reduced_controllable_input(trace_array, trace_n1fixed_array, counter_array, nonce_array, nonce_n1fixed_array, max_corr_per_sample, two_best_subkeys, show_progress=False, plot_corrs=False):
    if show_progress:
        if not two_best_subkeys:
            total = 12*4
        else:
            total = 12*15

        progress = tqdm(total=total, desc="progress")


    # init states

    state0 = initial_state()
    state1 = np.zeros((4, 4), dtype=np.int)


    # attack the second half of the key

    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 4, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 5, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 6, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 7, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)


    # attack several intermediate states to recover the first half of the state
    # after the first round

    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 8, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 9, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)

    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 10, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 11, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)

    state0, state1 = attack_subkey_word(trace_n1fixed_array, counter_array, nonce_n1fixed_array, 12, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_n1fixed_array, counter_array, nonce_n1fixed_array, 13, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)


    # extracted d2, a1 -> calculate d0, a0

    nonce_n1fixed0 = unpack_nonce(nonce_n1fixed_array[0])
    b0 = quarter_round(chacha_consts[2], state0[1,2], state0[2,2], nonce_n1fixed0[1])[1]
    a1 = state1[0,1]
    d2 = state1[3,0]

    a0 = SUB(a1, b0)
    d0 = ROTR(d2, 16) ^ a1

    state1[0,1] = a0
    state1[3,0] = d0


    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 14, state0, state1, max_corr_per_sample, two_best_subkeys, False, progress if show_progress else None, plot_corrs)
    state0, state1 = attack_subkey_word(trace_array, counter_array, nonce_array, 15, state0, state1, max_corr_per_sample, two_best_subkeys, True, progress if show_progress else None, plot_corrs)


    # extracted a1, b0 -> calculate a0, _

    b0 = state1[1,1]
    a1 = state1[0,0]
    a0 = SUB(a1, b0)

    state1[0,0] = a0


    # recover the first two columns of state_0

    for i in range(2):
        state0[:,i] = inv_quarter_round(*state1[:,i])


    if show_progress:
        progress.close()


    # extract the key from the state

    key = list(state0[1:3].flatten())

    counter0 = unpack_counter(counter_array[0])
    nonce0 = unpack_nonce(nonce_array[0])
    key_wrong = state0[0,0] != chacha_consts[0] or state0[0,1] != chacha_consts[1] or state0[3,0] != counter0 or state0[3,1] != nonce0[0]


    return key, key_wrong



# print state0 and state1
def print_states(state0, state1):
    state01 = (state0, state1)
    for i in range(2):
        print()
        for row in range(4):
            for col in range(4):
                print("%08x" % state01[i][row,col], end=(" " if col < 3 else "\n"))






if __name__ == "__main__":
    main()

