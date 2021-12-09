import abc

class EncryptionAlgorithm(metaclass=abc.ABCMeta):  #
    @abc.abstractmethod
    def encrypt(self):
        pass

    def decrypt(self):
        pass