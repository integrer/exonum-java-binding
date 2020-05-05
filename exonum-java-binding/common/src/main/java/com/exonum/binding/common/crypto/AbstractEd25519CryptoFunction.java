package com.exonum.binding.common.crypto;

import com.goterl.lazycode.lazysodium.LazySodium;

import static com.exonum.binding.common.crypto.CryptoFunctions.Ed25519.*;
import static com.exonum.binding.common.crypto.CryptoUtils.hasLength;
import static com.google.common.base.Preconditions.checkArgument;

public abstract class AbstractEd25519CryptoFunction implements CryptoFunction {

    abstract protected LazySodium getLazySodium();

    @Override
    public KeyPair generateKeyPair(byte[] seed) {
        checkArgument(hasLength(seed, SEED_BYTES),
                "Seed byte array has invalid size (%s), must be %s", seed.length, SEED_BYTES);

        byte[] publicKey = new byte[PUBLIC_KEY_BYTES];
        byte[] privateKey = new byte[PRIVATE_KEY_BYTES];

        if (!getLazySodium().cryptoSignSeedKeypair(publicKey, privateKey, seed)) {
            throw new RuntimeException("Failed to generate a key pair");
        }
        return KeyPair.newInstanceNoCopy(privateKey, publicKey);
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] publicKey = new byte[PUBLIC_KEY_BYTES];
        byte[] privateKey = new byte[PRIVATE_KEY_BYTES];

        if (!getLazySodium().cryptoSignKeypair(publicKey, privateKey)) {
            throw new RuntimeException("Failed to generate a key pair");
        }
        return KeyPair.newInstanceNoCopy(privateKey, publicKey);
    }

    @Override
    public byte[] signMessage(byte[] message, PrivateKey privateKey) {
        checkArgument(hasLength(privateKey.toBytesNoCopy(), PRIVATE_KEY_BYTES));
        byte[] signature = new byte[SIGNATURE_BYTES];
        boolean signed = getLazySodium().cryptoSignDetached(signature, message, message.length,
                privateKey.toBytesNoCopy());

        if (!signed) {
            throw new RuntimeException("Could not sign the message.");
        }
        return signature;
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, PublicKey publicKey) {
        checkArgument(hasLength(publicKey.toBytesNoCopy(), PUBLIC_KEY_BYTES),
                "Public key has invalid size (%s), must be %s", publicKey.size(), PUBLIC_KEY_BYTES);
        if (!hasLength(signature, SIGNATURE_BYTES)) {
            return false;
        }
        return getLazySodium()
                .cryptoSignVerifyDetached(signature, message, message.length, publicKey.toBytesNoCopy());
    }

}
