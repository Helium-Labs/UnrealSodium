#pragma once

#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"
#include "HAL/Platform.h"
#include "GenericPlatform/GenericPlatform.h"
#include "../../ThirdParty/libsodium/src/libsodium/include/sodium.h"

class UNREALSODIUM_API FUnrealSodiumModule : public IModuleInterface
{
public:

	////////////////////////////
	// IModuleInterface implementation
	////////////////////////////

	virtual void StartupModule() override;
	virtual void ShutdownModule() override;

	void GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& secretKey);
	TArray<uint8> GenerateKey();

	SIZE_T GetPublicKeyBytes() { return crypto_box_PUBLICKEYBYTES; }
	SIZE_T GetSecretKeyBytes() { return crypto_box_SECRETKEYBYTES; }
	SIZE_T GetBoxSealBytes() { return crypto_box_SEALBYTES; }
	SIZE_T GetMacBytes() { return crypto_box_MACBYTES; }
	SIZE_T GetMacBytesSymmetric() { return crypto_secretbox_MACBYTES; }

	SIZE_T GetAssymetricNonceLen() { return crypto_box_NONCEBYTES; }
	SIZE_T GetSymmetricNonceLen() { return crypto_secretbox_NONCEBYTES; }

	void RandomBytes(unsigned char* bytes, size_t len);

	// Hashing functions
	// SHA-256
	int32 SHA256HashBytes(TArray<uint8>& data, TArray<uint8>& outHash);
	// SHA-512
	int32 SHA512HashBytes(TArray<uint8>& data, TArray<uint8>& outHash);

	// Encoding functions
	// Base64
	int32 Base64Encode(TArray<uint8>& data, FString& outBase64);
	int32 Base64Decode(FString& base64, TArray<uint8>& outData);

	// XSalsa20 based asymmetric encryption
	int32 Encrypt(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& publicKey);
	int32 Decrypt(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& publicKey, TArray<uint8>& privateKey);

	int32 EncryptAuthenticated(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey);
	int32 DecryptAuthenticated(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey);

	// XSalsa20 based symmetric encryption and MAC 
	int32 EncryptSymmetric(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& key);
	int32 DecryptSymmetric(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& key);

	// AES-GCM based symmetric encryption and MAC
	int32 GenerateAES256GCMKey(TArray<uint8>& generatedKey);
	int32 GenerateAES256GCMNonce(TArray<uint8>& generatedNonce);
	int32 EncryptAES256GCM(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& key);
	int32 DecryptAES256GCM(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& key);

	// Key exchange
	// Derives a X25519 shared secret from the a senders public key and the receivers key pair
	int32 DeriveX25519SharedSecret(TArray<uint8>& theirPublicKey, TArray<uint8>& myPublicKey, TArray<uint8>& myPrivateKey, TArray<uint8>& sharedSecret);
	// Derives a X25519 shared secret from the a senders public key and the receivers key pair and hashes it with the each public key in a sorted order SHA-256. With the smaller key first.
	int32 DeriveX25519Sha256HashedSharedSecret(TArray<uint8>& theirPublicKey, TArray<uint8>& myPublicKey, TArray<uint8>& myPrivateKey, TArray<uint8>& sharedSecret);

	static inline FUnrealSodiumModule& Get() {
		return FModuleManager::LoadModuleChecked<FUnrealSodiumModule>("UnrealSodium"); // name should be the same as directory of the plugin in /Plugins
	}

	static inline bool IsAvailable() {
		return FModuleManager::Get().IsModuleLoaded("UnrealSodium");
	}

private:
	/** Handle to the test dll we will load */
	//void* libUnrealSodiumHandle;
};