

# Common functions and constants needed to calculate several internal states of
# the ChaCha algorithm.


from tqdm import tqdm, trange
import numpy as np
import struct


# constants used in the initial state
chacha_consts = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]


# hamming weight for 8 bits
HW8 = [bin(x).count("1") for x in range(256)]

# hamming weight
def HW(x):
    return bin(x).count("1")


# 32-bit rotate left
def ROTL(x, n):
    return ((x<<n) | (x>>(32-n))) & 0xFFFFFFFF

# 32-bit rotate right
def ROTR(x, n):
    return ((x>>n) | (x<<(32-n))) & 0xFFFFFFFF

# 32-bit add
def ADD(a, b):
    return (a+b) & 0xFFFFFFFF

# 32-bit subtract
def SUB(a, b):
    return (a-b+0x100000000) & 0xFFFFFFFF




# chacha intermediate functions

def intermediate_a(a0, b0, c, d0):
    d1 = d0 ^ ADD(a0, b0)
    return d1

def intermediate_b(a0, b0, c0, d0):
    d2 = ROTL(d0 ^ ADD(a0, b0), 16)
    b1 = b0 ^ ADD(c0, d2)
    return b1

def intermediate_c(a0, b0, c0, d0):
    a1 = ADD(a0, b0)
    d2 = ROTL(d0^a1, 16)

    c1 = ADD(c0, d2)
    b2 = ROTL(b0^c1, 12)

    a2 = ADD(a1, b2)
    d3 = d2^a2

    return d3

def intermediate_d(a0, b0, c0, d0):
    a1 = ADD(a0, b0)
    d2 = ROTL(d0^a1, 16)

    c1 = ADD(c0, d2)

    return c1

def intermediate_e(a, b0, c0, d2):
    b1 = b0 ^ ADD(c0, d2)
    return b1

def intermediate_f(a1, b0, c0, d2):
    b1 = b0 ^ ADD(c0, d2)
    d3 = d2 ^ ADD(a1, ROTL(b1, 12))

    return d3

def intermediate_g(a1, b, c0, d0):
    c1 = ADD(c0, ROTL(d0 ^ a1, 16))
    return c1

def intermediate_h(a1, b0, c0, d0):
    d2 = ROTL(d0 ^ a1, 16)
    b1 = b0 ^ ADD(c0, d2)

    return b1


# key_known=True when calculating intermediate for TVLA/NICV
def intermediate(step, state0, state1, key_known):
    # use meaningful names where possible
    consts = state0[0]
    subkeys = state0[1:3].flatten()
    counter = state0[3,0]
    nonce = state0[3,1:4]

    # output of the first round
    a0, b0, c0, d0 = state1[:,0]
    a1, b1, c1, d1 = state1[:,1]
    a2, b2, c2, d2 = state1[:,2]
    a3, b3, c3, d3 = state1[:,3]

    if step == 0:
        f = intermediate_a

        a = consts[0]
        b = subkeys[0]
        c = None
        d = counter
    elif step == 1:
        f = intermediate_a

        a = consts[1]
        b = subkeys[1]
        c = None
        d = nonce[0]
    elif step == 2:
        f = intermediate_b

        a = consts[0]
        b = subkeys[0]
        c = subkeys[4]
        d = counter
    elif step == 3:
        f = intermediate_b

        a = consts[1]
        b = subkeys[1]
        c = subkeys[5]
        d = nonce[0]
    elif step == 4:
        f = intermediate_a

        a = consts[2]
        b = subkeys[2]
        c = None
        d = nonce[1]
    elif step == 5:
        f = intermediate_a

        a = consts[3]
        b = subkeys[3]
        c = None
        d = nonce[2]
    elif step == 6:
        f = intermediate_b

        a = consts[2]
        b = subkeys[2]
        c = subkeys[6]
        d = nonce[1]
    elif step == 7:
        f = intermediate_b

        a = consts[3]
        b = subkeys[3]
        c = subkeys[7]
        d = nonce[2]
    elif step == 8:
        f = intermediate_a

        a = a3
        b = b0
        c = None
        d = d2
    elif step == 9:
        f = intermediate_b

        a = a3
        b = b0
        c = c1
        d = d2
    elif step == 10:
        f = intermediate_a

        a = a2
        b = b3
        c = None
        d = d1
    elif step == 11:
        f = intermediate_b

        a = a2
        b = b3
        c = c0
        d = d1
    elif step == 12:
        if key_known:
            f = intermediate_b

            a = a1
            b = b2
            c = c3
            d = d0
        else:
            f = intermediate_e

            a = None
            b = b2
            c = c3
            d = d0
    elif step == 13:
        if key_known:
            f = intermediate_c

            a = a1
            b = b2
            c = c3
            d = d0
        else:
            f = intermediate_f

            a = a1
            b = b2
            c = c3
            d = d0
    elif step == 14:
        if key_known:
            f = intermediate_d

            a = a0
            b = b1
            c = c2
            d = d3
        else:
            f = intermediate_g

            a = a0
            b = None
            c = c2
            d = d3
    elif step == 15:
        if key_known:
            f = intermediate_b

            a = a0
            b = b1
            c = c2
            d = d3
        else:
            f = intermediate_h

            a = a0
            b = b1
            c = c2
            d = d3


    return f(a, b, c, d)



# generates the initial state
def initial_state(key=[0]*8, counter=0, nonce=[0]*3):
    state = np.zeros((4, 4), dtype=np.int)

    state[0] = chacha_consts
    state[1] = key[0:4]
    state[2] = key[4:8]
    state[3] = [counter, *nonce]

    return state



# arrays of (state, row, col)
# specifies the subkey word which is calculated in the corresponding step

idx_subkey_by_step = [
    (0, 1, 0),          # 0             v4   -> key[0]
    (0, 1, 1),          # 1             v5   -> key[1]
    (0, 2, 0),          # 2             v8   -> key[4]
    (0, 2, 1),          # 3             v9   -> key[5]
    (0, 1, 2),          # 4             v6   -> key[2]
    (0, 1, 3),          # 5             v7   -> key[3]
    (0, 2, 2),          # 6             v10  -> key[6]
    (0, 2, 3),          # 7             v11  -> key[7]
    (1, 1, 0),          # 8             v4'  -> key[0]
    (1, 2, 1),          # 9             v9'  -> key[5]
    (1, 3, 1),          # 10            v13' -> nonce[0]
    (1, 2, 0),          # 11            v8'  -> key[4]
    (1, 3, 0),          # 12            v12' -> counter
    (1, 0, 1),          # 13            v1'  -> consts[1]
    (1, 0, 0),          # 14            v0'  -> consts[0]
    (1, 1, 1)           # 15            v5'  -> key[1]
]





# calculate correlations for a given trace and all 8-bit subkeys
def calc_corrs8(trace_array, counter_array, nonce_array, step, int_subkey, samples, state0, state1, subkey, show_progress=False):
    # copy the states because they are modified in this function

    state0 = np.copy(state0)
    state1 = np.copy(state1)

    state01 = (state0, state1)

    
    # bit position of the current subkey byte (for the input data)
    bit_pos = int_subkey*8

    # bit position of the current subkey byte (for the output of the intermediate)
    intermediate_bit_pos = bit_pos
    if step == 14:
        # shifting the result needed because of the ROTL operation in the intermediate function
        intermediate_bit_pos = (bit_pos+16)%32

    if show_progress:
        progress = tqdm(total=256, leave=False, desc="subkey guess")

    corrs = []
    for subkey_guess in range(256):
        # calculate the model

        model = []
        for i in range(len(trace_array)):
            counter = unpack_counter(counter_array[i])
            nonce = unpack_nonce(nonce_array[i])

            # set the counter and nonce in the state
            state0[3] = [counter, *nonce]

            if step >= 8:
                # run the first round for the third/4th column
                state1[:,2] = quarter_round(*state0[:,2])
                state1[:,3] = quarter_round(*state0[:,3])

            # set the subkey guess in the corresponding state
            state01[idx_subkey_by_step[step][0]][idx_subkey_by_step[step][1:3]] = (subkey_guess<<bit_pos) | subkey

            # calculate the intermediate value
            x = HW8[(intermediate(step, state0, state1, key_known=False)>>intermediate_bit_pos) & 0xFF]
            model.append(x)


        # calculate the correlation for each point

        corr_per_point = []
        for i in samples:
            corr = np.corrcoef(trace_array[:,i], model)[0,1]
            corr_per_point.append(corr)

        corrs.append(corr_per_point)

        if show_progress:
            progress.update()

    if show_progress:
        progress.close()

    return corrs


# calculate correlations for a given trace and all 32-bit subkeys
def calc_corrs32(trace_array, counter_array, nonce_array, step, samples, state0, state1, subkeys):
    # copy the states because they are modified in this function

    state0 = np.copy(state0)
    state1 = np.copy(state1)

    state01 = (state0, state1)


    corrs = []
    for subkey in subkeys:
        # calculate the model

        model = []
        for i in range(len(trace_array)):
            counter = unpack_counter(counter_array[i])
            nonce = unpack_nonce(nonce_array[i])

            # set the counter and nonce in the state
            state0[3] = [counter, *nonce]

            if step >= 8:
                # run the first round for the third/4th column
                state1[:,2] = quarter_round(*state0[:,2])
                state1[:,3] = quarter_round(*state0[:,3])

            # set the subkey guess in the corresponding state
            state01[idx_subkey_by_step[step][0]][idx_subkey_by_step[step][1:3]] = subkey

            # calculate the intermediate value
            x = HW(intermediate(step, state0, state1, key_known=False))
            model.append(x)


        # calculate the correlation for each point

        corr_per_point = []
        for i in samples:
            corr = np.corrcoef(trace_array[:,i], model)[0,1]
            corr_per_point.append(corr)

        corrs.append(corr_per_point)

    return corrs



# calculates a', b', c', d' for the given input (quarter round)
def quarter_round(a, b, c, d):
    a = ADD(a, b)
    d = ROTL(d^a, 16)

    c = ADD(c, d)
    b = ROTL(b^c, 12)

    a = ADD(a, b)
    d = ROTL(d^a, 8)

    c = ADD(c, d)
    b = ROTL(b^c, 7)

    return a, b, c, d


# calculates a', b', c', d' for the given input (inverse quarter round)
def inv_quarter_round(a, b, c, d):
    b = c ^ ROTR(b, 7)
    c = SUB(c, d)

    d = a ^ ROTR(d, 8)
    a = SUB(a, b)

    b = c ^ ROTR(b, 12)
    c = SUB(c, d)

    d = a ^ ROTR(d, 16)
    a = SUB(a, b)

    return a, b, c, d



# extracts a 32-bit subkey word from a key (32x 8-bit bytes)
def extract_subkey(key, n):
    return struct.unpack("<I", bytes(key[n*4:(n+1)*4]))[0]






# calculates a group for the given step and input data
def group32(step, counter, nonce, correct_key):
    counter = unpack_counter(counter)
    nonce = unpack_nonce(nonce)


    # construct states

    state0 = np.array([
        chacha_consts,
        [extract_subkey(correct_key, i) for i in range(0, 4)],
        [extract_subkey(correct_key, i) for i in range(4, 8)],
        [counter, *nonce]
    ])

    state1 = np.zeros((4, 4), dtype=np.int)
    for col in range(4):
        state1[:,col] = quarter_round(*state0[:,col])


    # calculate the hamming weight of the intermediate value
    
    hw = HW(intermediate(step, state0, state1, key_known=True))

    return hw >= 16


# calculates a group for the given step/byte and input data
def group8(step, int_subkey, counter, nonce, correct_key):
    counter = unpack_counter(counter)
    nonce = unpack_nonce(nonce)


    # construct states

    state0 = np.array([
        chacha_consts,
        [extract_subkey(correct_key, i) for i in range(0, 4)],
        [extract_subkey(correct_key, i) for i in range(4, 8)],
        [counter, *nonce]
    ])

    state1 = np.zeros((4, 4), dtype=np.int)
    for col in range(4):
        state1[:,col] = quarter_round(*state0[:,col])
    

    # bit position of the current subkey byte (for the output of the intermediate)
    intermediate_bit_pos = int_subkey*8
    if step == 14:
        # shifting the result needed because of the ROTL operation in the intermediate function
        intermediate_bit_pos = (intermediate_bit_pos+16)%32


    # calculate the hamming weight of the intermediate value

    hw = HW8[(intermediate(step, state0, state1, key_known=True)>>intermediate_bit_pos) & 0xFF]

    return hw >= 4



# calculate the three 32-bit words from 12 nonce bytes
def unpack_nonce(nonce):
    nonce = struct.unpack("<III", bytes(nonce))
    return nonce

# calculate the 32-bit word from 4 counter bytes
def unpack_counter(counter):
    counter = struct.unpack("<I", bytes(counter))[0]
    return counter

