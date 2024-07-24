import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import argparse
import os
from pathlib import Path
import logging
import binascii


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S',
    handlers=[
        logging.FileHandler("LockMyPix_decryption_log.log"),
        logging.StreamHandler()
    ]
)


# this is likley not a full list of the extensions possible
extension_map = {
    ".vp3": ".mp4",
    ".vo1": ".webm",
    ".v27": ".mpg",
    ".vb9": ".avi",
    ".v77": ".mov",
    ".v78": ".wmv",
    ".v82": ".dv",
    ".vz9": ".divx",
    ".vi3": ".ogv",
    ".v1u": ".h261",
    ".v6m": ".h264",
    ".6zu": ".jpg",
    ".tr7": ".gif",
    ".p50": ".png",
    ".8ur": ".bmp",
    ".33t": ".tiff",  # this extenion could also be .tif
    ".20i": ".webp",
    ".v93": ".heic",
    ".v91": ".flv",  # this key is linked to .flv and .eps
    ".v80": ".3gpp",
    ".vo4": ".ts",
    ".v99": ".mkv",
    ".vr2": ".mpeg",
    ".vv3": ".dpg",
    ".v81": ".rmvb",
    ".vz8": ".vob",
    ".wi2": ".asf",
    ".vi4": ".h263",
    ".v2u": ".f4v",
    ".v76": ".m4v",
    ".v75": ".ram",
    ".v74": ".rm",
    ".v3u": ".mts",
    ".v92": ".dng",
    ".r89": ".ps",
    ".v79": ".3gp",
}


def test_password(input_dir, password):
    for file in os.listdir(input_dir):
        if file.endswith(".6zu"):
            key = hashlib.sha1(password.encode()).digest()[:16]
            iv = key
            counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            encrypted_path = os.path.join(input_dir, os.fsdecode(file))
            with open(encrypted_path, "rb+") as enc_data:
                dec_data = cipher.decrypt(enc_data.read(16))
                header = binascii.hexlify(dec_data).decode("utf8")
                if header.startswith("ffd8ff"):
                    return True
                else:
                    logging.warning(f"{password} appears to be incorrect")
                    return False
        else:
            logging.warning("Cannot find a jpg file to test password")
            print("Password cannot be tested, do you want to continue anyway?")
            progress = ""
            while progress != "y" and progress != "n":
                progress = input("y/n: ").lower()
            if progress == "y":
                logging.info("Password check failed, user continued script")
                return True
            else:
                logging.warning("Password check failed, user stopped script")
                return False


def write_to_output(output_dir, filename, dec_data):
    basename, ext = os.path.splitext(filename)
    if extension_map.get(ext):
        filename += extension_map.get(ext)
    else:
        filename += ".unknown"
        logging.warning(f"File {filename} has an unknown extension")

    if not Path(output_dir).exists():
        logging.info(f"Making output directory: {output_dir}")
        os.mkdir(output_dir)

    with open(os.path.join(output_dir, filename), "wb") as f:
        f.write(dec_data)
        logging.info(f"decrypted file {filename} written to {output_dir}")


def decrypt_image(password, input_dir, output_dir):

    # the key is derived from the password hashed using SHA1
    logging.info("Decryption Started")
    logging.info(f"Password: {password}")
    logging.info(f"Input directory: {input_dir}")
    logging.info(f"Output directory: {output_dir}")

    key = hashlib.sha1(password.encode()).digest()[:16]
    iv = key  # iv is just the same as the key
    logging.info(f"AES decryption Key: {key}")
    logging.info(f"AES IV: {iv}")

    counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    if not Path(input_dir).exists():
        logging.warning(f"Cannot find the input directory: {input_dir}")
        raise SystemExit(1)  # quit if cannot read the input directory

    password_check = test_password(input_dir, password)
    if not password_check:
        logging.warning("Password check failed, check logs for reason")
        raise SystemExit(1)

    for file in os.listdir(input_dir):
        encrypted_file = os.fsdecode(file)
        encrypted_path = os.path.join(input_dir, os.fsdecode(file))
        with open(encrypted_path, "rb+") as enc_data:
            dec_data = cipher.decrypt(enc_data.read())
            write_to_output(output_dir, encrypted_file, dec_data)


def main():
    parser = argparse.ArgumentParser("LockMyPix Decrypt")
    parser.add_argument("password",
                        help="Enter the password for the application")

    parser.add_argument("input",
                        help="The directory of the exported encrypted files")

    parser.add_argument("output",
                        help="The directory for the decrypted files")

    args = parser.parse_args()
    decrypt_image(args.password, args.input, args.output)
    logging.info("Decryption Completed")


if __name__ == "__main__":
    main()
