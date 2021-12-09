import sys

from argparse import ArgumentParser, FileType

from EncryptionImplementationByAbstractClass.AES_RC4_EncryptionAlgorithm import AES_RC4_EncryptionAlgorithm
from EncryptionImplementationByAbstractClass.WordReversedAlgorithm import WordReverseEncryptionAlgorithm

from functools import wraps

def logger(orig_func):
    import logging
    logging.basicConfig(filename='./data/{}.log'.format(orig_func.__name__), level=logging.INFO)

    @wraps(orig_func)
    def wrapper(*args, **kwargs):
        logging.info(
            'Ran with args: {}, and kwargs: {}'.format(args, kwargs))
        return orig_func(*args, **kwargs)

    return wrapper


def timer(orig_func):
    import time

    @wraps(orig_func)
    def wrapper(*args, **kwargs):
        t1 = time.time()
        result = orig_func(*args, **kwargs)
        t2 = time.time() - t1
        print('{} ran in: {} sec'.format(orig_func.__name__, t2))
        return result

    return wrapper

@logger
def encryptFile(object, input_file, output_file, password):
    print('** Encrypt File **')

    object.encrypt(input_file, output_file)

    input_file.close()
    output_file.close()

@logger
def decryptFile(object, input_file, output_file, password=''):
    print('** Decrypt File **')

    object.decrypt(input_file, output_file)

    input_file.close()
    output_file.close()


def parse_cli():
    parser = ArgumentParser(description='** Encrypt/Decrypt Files Tools **')
    subparser = parser.add_subparsers(dest='subparser_name')

    decryptParser = subparser.add_parser('decrypt', help='Decrypt Files')
    decryptParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    decryptParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))
    decryptParser.add_argument('-e', '--encryption', required=True, metavar='ENCRYPTION', action='store',
                               choices=['WordReversed', 'RC4', 'AES'])
    decryptParser.add_argument('-p', '--password', required=False, metavar='PASSWORD')

    encryptParser = subparser.add_parser('encrypt', help='Encrypt Files')
    encryptParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    encryptParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))
    encryptParser.add_argument('-e', '--encryption', required=True, metavar='ENCRYPTION', action='store',
                               choices=['WordReversed', 'RC4', 'AES'])
    encryptParser.add_argument('-p', '--password', required=False, metavar='PASSWORD')

    if len(sys.argv) < 2:
        parser.print_help()

    return parser.parse_args()


@logger
@timer
def main():
    args = parse_cli()

    if args.subparser_name == 'decrypt':
        if args.encryption == 'WordReversed':
            decryptFile(WordReverseEncryptionAlgorithm(), args.input, args.output)
        elif args.encryption == 'RC4':
            decryptFile(AES_RC4_EncryptionAlgorithm(), args.input, args.output, args.password)
        else:
            print("Not Supported Decrypt Yet!")

    elif args.subparser_name == 'encrypt':
        if args.encryption == 'WordReversed':
            encryptFile(WordReverseEncryptionAlgorithm(), args.input, args.output, args.password)
        elif args.encryption == 'RC4':
            encryptFile(AES_RC4_EncryptionAlgorithm(),args.input, args.output, args.password)
        else:
            print("Not Supported Encrypt Yet!")
    # lines = ReadFile()


if __name__ == "__main__":
    main()
