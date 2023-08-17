def __generate_keys(self):
    if os.path.exists('server-keys'):
        if os.path.isfile('server-keys/server-privatekey.rsa') and os.path.isfile('server-keys/server-publickey.rsa'):
            self.logger.debug('Import keys')
            with open('server-keys/server-publickey.rsa', 'rb') as FilePubKey, open('server-keys/server-privatekey.rsa',
                                                                                    'rb') as FilePrivKey:
                UnloadServerPublicKey = FilePubKey.read()
                UnloadServerPrivateKey = FilePrivKey.read()
                self.ServerPublicKey = cPickle.loads(UnloadServerPublicKey)
                self.ServerPrivateKey = cPickle.loads(UnloadServerPrivateKey)
        else:
            self.logger.warning('Keys directory containing keys not found, generating new ones')
            with open('server-keys/server-publickey.rsa', 'wb') as FilePubKey, open('server-keys/server-privatekey.rsa',
                                                                                    'wb') as FilePrivKey:
                pubkey, privkey = rsa.newkeys(2048)
                FilePubKey.write(cPickle.dumps(pubkey))
                FilePrivKey.write(cPickle.dumps(privkey))
                self.ServerPrivateKey = privkey
                self.ServerPublicKey = pubkey
    else:
        self.logger.warning('Keys directory containing keys not found, generating new ones')
        os.mkdir('server-keys')
        with open('server-keys/server-publickey.rsa', 'wb') as FilePubKey, open('server-keys/server-privatekey.rsa',
                                                                                'wb') as FilePrivKey:
            pubkey, privkey = rsa.newkeys(2048)
            FilePubKey.write(cPickle.dumps(pubkey))
            FilePrivKey.write(cPickle.dumps(privkey))
            self.ServerPrivateKey = privkey
            self.ServerPublicKey = pubkey

@staticmethod
def __parse_package(CompressedPackage: bytes, PrivateKey):
    DecryptedPackage = rsa.decrypt(CompressedPackage, PrivateKey)
    DecompressedPackage = zlib.decompress(DecryptedPackage)

    ID, Body = DecompressedPackage[:2], DecompressedPackage[2:]
    ID = struct.unpack('!H', ID)[0]
    return ID, Body

@staticmethod
def __create_package(ID: int, Body: bytes, PublicKey):
    PackedID = struct.pack('!H', ID)
    package = PackedID + Body

    CompressedPackage = zlib.compress(package, zlib.Z_BEST_COMPRESSION)
    print(CompressedPackage)
    print(len(CompressedPackage))
    EncryptedPackage = rsa.encrypt(CompressedPackage, PublicKey)

    return EncryptedPackage