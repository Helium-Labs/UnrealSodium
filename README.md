![UnrealSodium](https://raw.githubusercontent.com/Helium-Labs/UnrealSodium/master/logo.png)
============

An easy to use public and private cryptography plugin for Unreal Engine 5 based on libsodium.

It currently works only on Win64 builds of UE5. Support for Android, iOS, Linux and MacOS are planned, but not guaranteed to happen. The plugin is very simple due to the portable nature of libsodium and it is compatible with most versions of UE5.

Last tested on: **5.1.0**

## Installation

1. *git clone --recursive* this repository to your UnrealProject/Plugins/ folder.
2. In the Source\ThirdParty\libsodium\libsodium.sln, change the Visual Studio platform toolset to v142 to match the Unreal Engine 5 VS configuration and then compile it. This step will generate the sodium library. Use x64 and Release options as target.
3. Regenerate code for your UE5 project (right click YourGame.uproject to do it)
4. Add "UnrealSodium" to YourGame.Build.cs in PublicDependencyModuleNames.
5. Open and Build your game in Visual Studio.
6. Start the editor as usual, allow it to compile UnrealSodium, this should only happen once.
7. Build/Package your game as you normally would.

Contributions are warmly welcomed to further enhance the compatibility and usability of Unreal Engine Sodium with UE5. 

# Usage

![Public encryption](http://i.imgur.com/ezgBj7v.jpg)

# Available Blueprint Functions
## Random Number Generation

On Unix-based systems and on Windows, Sodium uses the facilities provided by the operating system when generating random numbers is required (CS PRNG or TRNG).

*   `RandomBytes(int32 len)` : Generates a sequence of random bytes with the specified length.
## Encoding
### Base64
*   `ToBase64(TArray<uint8> data)` : Converts the input byte array into a base64-encoded string.
*   `ToBase64S(FString data)` : Converts the input string into a base64-encoded string.
*   `FromBase64(FString data, bool& success)` : Converts a base64-encoded string into a byte array. Returns the success of the operation.
*   `FromBase64S(FString data, bool& success)` : Converts a base64-encoded string back into a normal string. Returns the success of the operation.
## One-Way Hashing
### Sha256
*   `ToSha256Hash(TArray<uint8> data, TArray<uint8>& hashedData, bool& success)` : Converts the input byte array into a SHA256 hashed byte array. Returns the success of the operation.
*   `ToSha256HashAsB64String(TArray<uint8> data, FString& hashedData, bool& success)` : Converts the input byte array into a SHA256 hashed base64 string. Returns the success of the operation.
### Sha512
*   `ToSha512Hash(TArray<uint8> data, TArray<uint8>& hashedData, bool& success)` : Converts the input byte array into a SHA512 hashed byte array. Returns the success of the operation.
*   `ToSha512HashAsB64String(TArray<uint8> data, FString& hashedData, bool& success)` : Converts the input byte array into a SHA512 hashed base64 string. Returns the success of the operation.
## Asymmetric Public Key Cryptography
### X25519 Key derivation
*   `GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& privateKey)` : Generates a public and private key pair.
### XSalsa20 Stream Cipher
*   `EncryptString(FString s, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success)` : Encrypts a string with a public key using XSalsa20-Poly1305.
*   `DecryptString(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, FString& decrypted, bool& success)` : Decrypts a string with a public key and a private key using XSalsa20-Poly1305.
*   `Encrypt(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success)` : Encrypts a byte array with a public key using XSalsa20-Poly1305.
*   `Decrypt(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8>& decrypted, bool& success)` : Decrypts a byte array with a public key and a private key using XSalsa20-Poly1305.
*   `EncryptAuthenticated(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success)` : Encrypts a byte array with a public key, private key, and nonce using XSalsa20-Poly1305 with Poly1305 for authentication.
*   `DecryptAuthenticated(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success)` : Decrypts an authenticated byte array with a public key, private key, and nonce using XSalsa20-Poly1305 with Poly1305 for authentication.
## Symmetric Secret Key Cryptography
### XSalsa20 Stream Cipher
*   `EncryptStringSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success)` : Encrypts a string with a key and a nonce using XSalsa20.
*   `DecryptStringSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success)` : Decrypts a string with a key and a nonce using XSalsa20.
*   `EncryptSymmetric(TArray<uint8> data, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success)` : Encrypts a byte array with a key and a nonce using XSalsa20.
*   `DecryptSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success)` : Decrypts a byte array with a key and a nonce using XSalsa20.
### AES Block Cipher
Despite its popularity in TLS, the secure application of AES-GCM outside this context is complex, especially when encrypting more than ~350GB of data with a specific key. Additionally, unique nonces are crucial for maintaining security in AES-GCM, though setting up atomic counters for this purpose can be challenging in a distributed environment. Make sure the nonces aren't repeated for a given secret key. Nonces are 12 bytes, and have a similar purpose to the Initialization Vector (IV) (used in-place of IV).

*   `GenerateAES256GCMKey(TArray<uint8>& key, bool& success)` : Generates an AES256-GCM encryption key. The success of the operation is returned.
*   `GenerateAES256GCMNonce(TArray<uint8>& generatedNonce)` : Generates a nonce for AES256-GCM encryption.
*   `EncryptStringAES256GCMSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success)` : Encrypts a string with a key and a nonce using AES256-GCM. The success of the operation is returned.
*   `DecryptStringAES256GCMSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success)` : Decrypts a string with a key and a nonce using AES256-GCM. The success of the operation is returned.

## Key Exchange
*   `DeriveX25519SharedSecret(TArray<uint8> theirPublicKey, TArray<uint8> myPublicKey, TArray<uint8> myPrivateKey, TArray<uint8>& sharedSecret, bool& success)` : Derives a shared secret from the other party's public key and your own key pair with X25519 ECDH scalar mult.
*   `DeriveX25519Sha256HashedSharedSecret(TArray<uint8> theirPublicKey, TArray<uint8> myPublicKey, TArray<uint8> myPrivateKey, TArray<uint8>& sharedSecret, bool& success)` : Derives a shared secret from the other party's public key and your own key pair using the X25519 ECDH, and then SHA256 hashes the result the public keys in ascending order for enhanced security.

# What exactly is the Libsodium Cryptography Library?

![libsodium](https://raw.github.com/jedisct1/libsodium/master/logo.png)

Libsodium is a modern, versatile software library designed for encryption, decryption, signatures, password hashing, and more.

Originating as a fork of [NaCl](http://nacl.cr.yp.to/), it offers a compatible API and additional enhancements to further improve usability. Its goal is to offer core operations essential for the development of higher-level cryptographic tools.

One of Libsodium's strengths is its portability. It is cross-compilable and supports a wide array of compilers and operating systems, including Windows (MingW or Visual Studio, x86 and x64), iOS, Android, along with Javascript and Webassembly compatibility.

## Documentation
You can access the official documentation [here](https://doc.libsodium.org), which is maintained on Gitbook and built from the [libsodium-doc](https://github.com/jedisct1/libsodium-doc) repository.

## Integrity Checking
Detailed integrity checking instructions, including the signing key for Libsodium, can be found in the [installation](https://download.libsodium.org/doc/installation#integrity-checking) section of the documentation.


# License
https://opensource.org/licenses/MIT

## libsodium license:
https://opensource.org/licenses/ISC

## Legal Disclaimer

We reserve the right to change anything at anytime, without notice. Anything said is not necessarily represenative of the final product. No liabilities or warranties whatsoever, per the attached license.

# Tags

libsodium, encryption, cryptography, UnrealEngine, UnrealEngine5, UE5, UnrealSodium, libsodium-ue5, game-development, encryption-library, game-engine, game-plugin

