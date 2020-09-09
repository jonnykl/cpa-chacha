

# Common functions for scope/target handling and loading sets of traces.


import chipwhisperer as cw
import time
import numpy as np




# reset target
def reset_target(scope):
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high"
    time.sleep(0.05)


# init scope and reset target
# returns scope, target and programmer
def init_scope():
    scope = cw.scope()
    target = cw.target(scope)

    prog = cw.programmers.STM32FProgrammer

    time.sleep(0.05)
    scope.default_setup()

    reset_target(scope)
    time.sleep(0.05)

    return scope, target, prog


# load previously captured traces
# returns arrays of: traces, counters, nonces; known key
def load_traces(filename="traces.npy", N=None):
    data = np.load(filename)
    if N is None:
        N = data["trace_array"].shape[0]

    known_key = None
    if "known_key" in data:
        known_key = data["known_key"]
        if len(known_key) == 0:
            known_key = None

    return data["trace_array"][:N], data["counter_array"][:N], data["nonce_array"][:N], known_key

