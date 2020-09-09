#!/usr/bin/env python3


# Tests the ChaCha implementation of the target using a known-answe-test.


from common import *

from chipwhisperer.common.utils import util
import argparse



def main():
    # parse args

    parser = argparse.ArgumentParser(description="Test ChaCha implementation with a known-answer-test")
    parser.parse_args()


    # init scope, target

    scope, target, _ = init_scope()

    target.output_len = 0


    # test data

    key = util.hexStrToByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F")
    nonce = util.hexStrToByteArray("00 00 00 09 00 00 00 4A 00 00 00 00")
    counter = util.hexStrToByteArray("01 00 00 00")

    pt_a = bytes([0]*32)
    pt_b = bytes([0]*32)

    expected_ct_a = util.hexStrToByteArray("10 F1 E7 E4 D1 3B 59 15 50 0F DD 1F A3 20 71 C4 C7 D1 F4 C7 33 C0 68 03 04 22 AA 9A C3 D4 6C 4E")
    expected_ct_b = util.hexStrToByteArray("D2 82 64 46 07 9F AA 09 14 C2 D7 05 D9 8B 02 A2 B5 12 9C D1 DE 16 4E B9 CB D0 83 E8 A2 50 3C 4E")


    # send test data to the target

    target.simpleserial_write('c', counter)
    if target.simpleserial_wait_ack(timeout=250) is None:
        raise Warning("Device failed to ack")

    target.simpleserial_write('n', nonce)
    if target.simpleserial_wait_ack(timeout=250) is None:
        raise Warning("Device failed to ack")

    target.simpleserial_write('a', pt_a)
    if target.simpleserial_wait_ack(timeout=250) is None:
        raise Warning("Device failed to ack")

    target.simpleserial_write('b', pt_b)
    if target.simpleserial_wait_ack(timeout=250) is None:
        raise Warning("Device failed to ack")

    
    # capture a trace (performs the encrpytion)

    cw.capture_trace(scope, target, bytes(1), key)


    # read the encrypted data

    target.simpleserial_write('A', bytes())
    ct_a = target.simpleserial_read('A', 32)
    target.simpleserial_write('B', bytes())
    ct_b = target.simpleserial_read('B', 32)


    # compare read ciphertext with expected ciphertext

    if ct_a == expected_ct_a and ct_b == expected_ct_b:
        print("OK")
    else:
        print("FAIL")




if __name__ == "__main__":
    main()

