
# Setup environment

    $ virtualenv -p python3 venv
    $ source venv/bin/activate
    $ pip install -r requirements.txt


# Instructions

**Note:** A help text is available for all python scripts using the *-h* option.


Execute once:

    $ ./build_target.sh
    $ ./program_target.py
    $ mkdir -p traces && cd traces
    $ ../capture_traces.py -r
    $ ../capture_traces.py -r -1 traces_*.npz
    $ cd ..

Then execute:

    $ ./tvla_calc_subkey_samples.py traces/traces_[0-9].npz

After that the attack can be performed:

    $ ./attack.py -r -s traces/traces_0.npz

If the key is not correct, you can retry it with an added effort:

    $ ./attack.py -r -s -t traces/traces_0.npz

Multiple sets of traces (with different keys) can be tested concurrently:

    $ ./attack_test.py -r -s traces/traces_*.npz

At the end a statistic of all results of the attacks will be printed.


# Additional miscellaneous scripts

    $ ./test_chacha_implementation.py
    $ ./plot_trace.py traces/traces_0.npz
    $ ./tvla_specific.py traces/traces_0.npz
    $ ./nicv.py traces/traces_0.npz

