from EncryptionImplementationByAbstractClass.EncryptionAlgorithmInterface import EncryptionAlgorithm
import re

class WordReverseEncryptionAlgorithm(EncryptionAlgorithm):
    def encrypt(self, input_file, output_file):
        print("Try to encrypt ", input_file)
        print("Encrypting with word reversed...")

        for line in input_file.readlines():
            # output_file.write(line[-2::-1]+"\n")
            for word in re.split(r"([.。！!?？；;，,\s+])", line.decode("utf-8")):
                try:
                    output_file.write(word.encode('utf-8')[::-1])
                except Exception as e:
                    print("output file can't write successfully for the reason:{}", e)


        print("Encrypted successfully")



    def decrypt(self, input_file, output_file):
        print("Try to decrypt ", input_file)
        print("Decrypting with word reversed...")
        for line in input_file.readlines():
            for word in re.split(r"([.。！!?？；;，,\s+])", line.decode("utf-8")):
                try:
                    output_file.write(word.encode('utf-8')[::-1])
                except Exception as e:
                    print("output file can't write successfully for the reason:{}", e)

        print("Decrypted successfully")

