import abc
import fileinput
import sys, os, struct
# import fileinput
import re
from argparse import ArgumentParser, FileType
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA1, SHA256
from cryptography.hazmat.primitives.hmac import HMAC

MAGIC_ENCRYPTED_WORDREVERSED = 0x7191A8EF   #0x6C6C6568
MAGIC_ENCRYPTED_RC4 = 0x7291A8EF
MAGIC_ENCRYPTED_AES = 0X7391A8EF
MAGIC_PLAINTEXT = 0xB1A1AC88
RC4_SKIP = 0x300
AES_SKIP = 0x10
WORDREVERSED_SKIP = 0x666

class EncryptionAlgorithm(metaclass=abc.ABCMeta):  #
    @abc.abstractmethod
    def encrypt(self):
        pass

    def decrypt(self):
        pass


def get_header(input_file):
    input_file.seek(0, 0)
    data = input_file.read(8)
    header = struct.unpack('<II', data)
    return header[0], header[1]

def get_salt(input_file):
    input_file.seek(8, 0)
    return input_file.read(32)

def get_signature(input_file):
    input_file.seek(40, 0)
    return input_file.read(32)

def get_magic_check_rc4(input_file):
    input_file.seek(40, 0)
    return input_file.read(4)

def get_magic_check_aes(input_file):
    input_file.seek(72, 0)
    return input_file.read(4)

def check_password(cipher, magic_check):
    data = cipher.update(magic_check)
    decrypted_magic_check = struct.unpack('<I', data)
    return decrypted_magic_check[0] == MAGIC_PLAINTEXT

def make_salt(size):
    return os.urandom(size)

def extract_data(input_file):
    raw_len = input_file.read(4)
    if len(raw_len) != 4:
        raise EOFError('EOF')
    data_len = struct.unpack('<I', raw_len)[0]

    raw_data = input_file.read(data_len)
    if len(raw_data) != data_len:
        raise EOFError('EOF')
    return raw_data

def setup_cipher_wordreversed(salt, encrypt = False):
    hash = Hash(SHA1(), default_backend())
    hash.update(salt + bytes('wrdreversed', 'ascii'))
    cipher = Cipher((hash.finalize()), None, default_backend())
    cryptor = cipher.encryptor() if encrypt else cipher.decryptor()
    cryptor.update(bytes(WORDREVERSED_SKIP))
    return cryptor

def setup_cipher_rc4(salt, password, encrypt = False):
    hash = Hash(SHA1(), default_backend())
    hash.update(salt + bytes(password, 'ascii'))
    cipher = Cipher(algorithms.ARC4(hash.finalize()), None, default_backend())
    cryptor = cipher.encryptor() if encrypt else cipher.decryptor()
    cryptor.update(bytes(RC4_SKIP))
    return cryptor

def setup_cipher_aes(salt, password, encrypt = False):
    hash = Hash(SHA256(), default_backend())
    hash.update(salt + bytes(password, 'ascii'))
    cipher = Cipher(algorithms.AES(hash.finalize()[:16]), modes.CTR(salt[:16]), default_backend())
    cryptor = cipher.encryptor() if encrypt else cipher.decryptor()
    cryptor.update(bytes(AES_SKIP))
    return cryptor

def setup_hmac_aes(salt, password):
    hash = Hash(SHA256(), default_backend())
    hash.update(salt + bytes(password, 'ascii'))
    hmac = HMAC(hash.finalize()[16:], SHA256(), default_backend())
    return hmac

def create_write_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def get_file_list(path):
    file_list = []

    original_path = os.getcwd()
    os.chdir(path)
    for root, dirs, files in os.walk(".."):
        file_path = root.split(os.sep)[1:]
        file_path = '/'.join(file_path)
        if file_path:
            file_path += '/'
        for file in files:
            # check if both idx and dat files exist
            if file.endswith(".idx") and file[:-3] + "dat" in files:
                file_list.append(file_path + file[:-4])
    os.chdir(original_path)

    return file_list

def write_data(output_file, data):
    data_len = struct.pack('<I', len(data))
    output_file.write(data_len)
    output_file.write(data)

def unpack(input_file, unpack_directory):
        print('** Unpack File **')
        magic, length = get_header(input_file)

        if magic in (MAGIC_ENCRYPTED_RC4, MAGIC_ENCRYPTED_AES):
            print("EncryptFileTool Encrypted File")
            print("Cannot unpack encrypted File!")
            print("Decrypt File first!")

        elif magic == MAGIC_PLAINTEXT:
            print("EncryptFileTool Plaintext File")
            print("Length:", length, "bytes")

            print("Extracting File...")
            files_num = unpack_files(input_file, length, unpack_directory)
            if files_num > 0:
                print("Wrote", files_num, "files pair in:", unpack_directory)

        else:
            print("Invalid file!")
            print("Cannot unpack!")

        input_file.close()


def pack(output_file, pack_directory):
    print('** Pack File **')

    file_names = get_file_list(pack_directory)
    if len(file_names) > 0:
        print("Creating plaintext File with", len(file_names), "files pair...")
        pack_files(pack_directory, file_names, output_file)
        print("Done!")
    else:
        print("Error! No IDX and DAT files found!")

    output_file.close()

def unpack_files(input_file, file_length, path):
    count = 0
    input_file.seek(8, 0) # skip magic, length

    path = os.path.join(path, '')
    if os.path.exists(path):
        print("Directory", os.path.basename(path) , "already exists, cannot extract!")
        return count

    while input_file.tell() < file_length:
        try:
            name = extract_data(input_file).decode('ascii')
            idx = extract_data(input_file)
            dat = extract_data(input_file)

            create_write_file(path + name + '.idx', idx)
            create_write_file(path + name + '.dat', dat)

            count += 1
        except EOFError:
            print("Unexpected End of File!")
            break
    return count

def pack_files(path, file_names, output_file):
    output_file.seek(0, 0)
    magic = struct.pack('<I', MAGIC_PLAINTEXT)
    output_file.write(magic + bytes(4)) # magic, length offset

    path = os.path.join(path, '')
    for name in file_names:
        with open(path + name + '.idx', "rb") as idx_file:
            idx = idx_file.read()
        with open(path + name + '.dat', "rb") as dat_file:
            dat = dat_file.read()

        write_data(output_file, name.encode('ascii'))
        write_data(output_file, idx)
        write_data(output_file, dat)

    length = struct.pack('<I', output_file.tell()) # length
    output_file.seek(4, 0)
    output_file.write(length)

def encrypt_file_wordreversed(input_file, output_file, cipher, salt):
    input_file.seek(8, 0) # skip magic, length
    output_file.seek(0, 0)
    magic = struct.pack('<I', MAGIC_ENCRYPTED_WORDREVERSED)
    output_file.write(magic + bytes(4) + salt) # magic, length offset, salt

    magic_check = struct.pack('<I', MAGIC_PLAINTEXT)
    output_file.write(cipher.update(magic_check))

    while True:
        chunk = input_file.read(1024)
        if not chunk:
            break
        output_file.write(cipher.update(chunk))

    length = struct.pack('<I', output_file.tell()) # length
    output_file.seek(4, 0)
    output_file.write(length)

class WordReverseEncryption(EncryptionAlgorithm):
    def encrypt(self, input_file, output_file):
        print("Try to encrypt ", input_file)
        magic, length = get_header(input_file)

        print("****(hex)", hex(magic))

        if magic in (MAGIC_ENCRYPTED_RC4, MAGIC_ENCRYPTED_AES, MAGIC_ENCRYPTED_WORDREVERSED):
            print("EncryptFileTool Encrypted File")
            print("No encryption needed!")

        elif magic == MAGIC_PLAINTEXT:  #MAGIC_PLAINTEXT
            print("EncryptFileTool Plaintext File")
            print("Length:", length, "bytes")

            # if encryption == "WordReversed":
            salt = make_salt(32)
            print("Generated Salt (hex):", salt.hex())

            cipher = setup_cipher_wordreversed(salt, encrypt=True)

            print("Encrypting with word reversed...")
            encrypt_file_wordreversed(input_file, output_file, cipher, salt)
            print("Encrypted correctly")

            #
            # elif encryption == "RC4":
            #     salt = make_salt(32)
            #     print("Generated Salt (hex):", salt.hex())
            #
            #     cipher = setup_cipher_rc4(salt, password, encrypt=True)
            #
            #     print("Encrypting with rc4-sha1...")
            #     encrypt_File_rc4(input_file, output_file, cipher, salt)
            #     print("Encrypted correctly")
            # elif encryption == "AES":
            #     salt = make_salt(32)
            #     print("Generated Salt (hex):", salt.hex())
            #
            #     cipher = setup_cipher_aes(salt, password, encrypt=True)
            #     hmac = setup_hmac_aes(salt, password)
            #
            #     print("Encrypting with aes128-ctr-sha256...")
            #     encrypt_File_aes(input_file, output_file, cipher, hmac, salt)
            #     print("Encrypted correctly")
            # else:
            #     assert False

        else:
            print("Invalid file!")
            print("Cannot encrypt!")


        # with open(input_file, 'r', encoding='utf-8') as fin:
        #     lines = fin.readlines()
            # print(lines)
        # with open(output_file, 'w', encoding='utf-8') as out:reversed(list)
        # with fileinput.input(input_file) as f:
        #
        #     for line in f:
        #         line = ''.join(list(reversed(line)))
        #         print("encrypt:", line)
        #         # wordlist = re.split(r'\s+', line)
        #         # out.writelines(line)

        # for line in fileinput.input(files=(input_file)):
        #      print(line)


    def decrypt(self, input_file, output_file):
        # with open(output_file, 'w', encoding='utf-8') as out:
            for line in reversed(list(fileinput.input(input_file))):
                print("decrypt:", line)
                # out.writelines(line)



# def decrypt(self, , input_file, output_file):
#         return self.encrypt(self, word)


def encrypt(object, input_file, output_file):
    object.encrypt(input_file, output_file)

def decrypt(object, input_file, output_file):
    object.decrypt(input_file, output_file)


def encryptFile(object, input_file, output_file, password):
    print('** Encrypt File **')

    object.encrypt(input_file, output_file)

    input_file.close()
    output_file.close()


def decryptFile(object, input_file, output_file, password):
    print('** Decrypt File **')

    object.decrypt(input_file, output_file)

    input_file.close()
    output_file.close()


def parse_cli():
    parser = ArgumentParser(description='** Encrypt/Decrypt Files Tools **')
    subparser = parser.add_subparsers(dest='subparser_name')

    decryptParser = subparser.add_parser('decrypt', help='Decrypt Files')
    decryptParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    decryptParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('xb'))
    decryptParser.add_argument('-p', '--password', required=False, metavar='PASSWORD')

    encryptParser = subparser.add_parser('encrypt', help='Encrypt Files')
    encryptParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    encryptParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('xb'))
    encryptParser.add_argument('-e', '--encryption', required=True, metavar='ENCRYPTION', action='store',
                               choices=['WordReversed', 'RC4', 'AES'])
    encryptParser.add_argument('-p', '--password', required=False, metavar='PASSWORD')

    unpackParser = subparser.add_parser('unpack', help='Unpack backup')
    unpackParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    unpackParser.add_argument('-d', '--directory', required=True, metavar='UNPACK_DIRECTORY')

    packParser = subparser.add_parser('pack', help='Pack backup')
    packParser.add_argument('-d', '--directory', required=True, metavar='PACK_DIRECTORY')
    packParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('xb'))

    if len(sys.argv) < 2:
        parser.print_help()

    return parser.parse_args()


def main():
    args = parse_cli()

    if args.subparser_name == 'decrypt':
        decryptFile(args.input, args.output, args.password)
    elif args.subparser_name == 'encrypt':
        if args.encryption == 'WordReversed':
            encryptFile(WordReverseEncryption(), args.input, args.output, args.password)
        else:
            print("Not Supported Yet!")
    # lines = ReadFile()


if __name__ == "__main__":
    main()
