import argparse
import os
import sys
from getpass import getpass

import Crypto.Random as rand

from archive import generate_archive, parse_archive
from cipher import generate_key_from_password, encipher, decipher, generate_key_from_password_with_salt

DESCRIPTION = "Encrypt or decrypt a file using AES-GCM"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("action", help="encrypt or decrypt")
    parser.add_argument("file", help="file to encrypt or decrypt")
    parser.add_argument("-p", "--password", help="password to use for encryption or decryption")
    parser.add_argument("-r", "--randomize", help="randomize the filename written to", action="store_true")
    args = parser.parse_args()

    # check if file exists
    if not os.path.isfile(args.file):
        print(f"{args.file} does not exist")
        sys.exit(1)

    # check if action is valid
    if args.action not in ["encrypt", "decrypt"]:
        print("Invalid action")
        sys.exit(1)

    # check if password is provided
    if args.password is None:
        args.password = getpass("Password: ")

    # check if randomize is provided
    if args.randomize is None:
        args.randomize = False

    # generate key from password
    key, salt = generate_key_from_password(args.password)

    # encrypt or decrypt file
    if args.action == "encrypt":
        with open(args.file, "rb") as f:
            plaintext = f.read()
            iv, tag, ciphertext = encipher(key, plaintext)
            filename = args.file + ".enc"

            if args.randomize:
                filename = rand.get_random_bytes(16).hex() + ".enc"

            archive = generate_archive(iv, tag, salt, ciphertext)

        with open(filename, "wb") as f:
            f.seek(0)
            f.truncate()
            f.write(archive)
    elif args.action == "decrypt":
        with open(args.file, "rb") as f:
            data = f.read()
            iv, tag, salt, ciphertext = parse_archive(data)
            key = generate_key_from_password_with_salt(args.password, salt)
            plaintext = decipher(key, iv, tag, ciphertext)

        with open(args.file, "wb") as f:
            f.seek(0)
            f.truncate()
            f.write(plaintext)


if __name__ == "__main__":
    main()
