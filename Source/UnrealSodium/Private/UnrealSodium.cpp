#include "UnrealSodium.h"
#include "UnrealSodiumPrivatePCH.h"
#include "Core.h"
#include "Interfaces/IPluginManager.h"
#include "Misc/Base64.h"

#define LOCTEXT_NAMESPACE "FUnrealSodiumModule"

void FUnrealSodiumModule::StartupModule()
{
	sodium_init();
}

void FUnrealSodiumModule::ShutdownModule()
{
}

//////////////////////////////////////////////////////////////////////////
// Sodium API
//////////////////////////////////////////////////////////////////////////

void FUnrealSodiumModule::GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& secretKey) {
	auto sodium = FUnrealSodiumModule::Get();

	// allocate space for key
	publicKey.SetNum(sodium.GetPublicKeyBytes());
	secretKey.SetNum(sodium.GetSecretKeyBytes());

	// generate key
	crypto_box_keypair(publicKey.GetData(), secretKey.GetData());
}

void FUnrealSodiumModule::RandomBytes(unsigned char* bytes, size_t len) {
	randombytes_buf(bytes, len);
}

//////////////////////////////////////////////////////////////////////////
// Hashing
//////////////////////////////////////////////////////////////////////////
// SHA-256
int32 FUnrealSodiumModule::SHA256HashBytes(TArray<uint8>& data, TArray<uint8>& outHash) {
	outHash.SetNum(crypto_hash_sha256_BYTES);
	return crypto_hash_sha256(outHash.GetData(), data.GetData(), data.Num());
}

int32 FUnrealSodiumModule::SHA512HashBytes(TArray<uint8>& data, TArray<uint8>& outHash) {
	outHash.SetNum(crypto_hash_sha512_BYTES);
	return crypto_hash_sha512(outHash.GetData(), data.GetData(), data.Num());
}

//////////////////////////////////////////////////////////////////////////
// Encoding
//////////////////////////////////////////////////////////////////////////
// Base64
int32 FUnrealSodiumModule::Base64Encode(TArray<uint8>& data, FString& outBase64) {
	outBase64 = FBase64::Encode(data);
	return 0;
}

int32 FUnrealSodiumModule::Base64Decode(FString& base64, TArray<uint8>& outData) {
	if (FBase64::Decode(base64, outData)) {
		return 0;
	}
	return -1;
}

//////////////////////////////////////////////////////////////////////////
// Asymmetric
//////////////////////////////////////////////////////////////////////////
// Sealed boxes
// Sealed boxes are designed to anonymously send messages to a recipient given their public key. X25519 and XSalsa20-Poly1305 based.
int32 FUnrealSodiumModule::Encrypt(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& publicKey) {
	encrypted.SetNum(data.Num() + crypto_box_SEALBYTES);
	return crypto_box_seal(encrypted.GetData(), data.GetData(), data.Num(), publicKey.GetData());
}

int32 FUnrealSodiumModule::Decrypt(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	decrypted.SetNum(encrypted.Num() - crypto_box_SEALBYTES);
	return crypto_box_seal_open(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), publicKey.GetData(), privateKey.GetData());
}
// Authenticated encryption
// Encryption relying on a shared secret key that is derived from two sets of keys. Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305.
int32 FUnrealSodiumModule::EncryptAuthenticated(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	encrypted.SetNum(data.Num() + crypto_box_MACBYTES);
	return crypto_box_easy(encrypted.GetData(), data.GetData(), data.Num(), nonce.GetData(), publicKey.GetData(), privateKey.GetData());
}

int32 FUnrealSodiumModule::DecryptAuthenticated(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	decrypted.SetNum(encrypted.Num() - crypto_box_MACBYTES);
	return crypto_box_open_easy(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), nonce.GetData(), publicKey.GetData(), privateKey.GetData());
}

//////////////////////////////////////////////////////////////////////////
// Symmetric
//////////////////////////////////////////////////////////////////////////
// Stream ciphers
// XSalsa20
// Encrypts a message with a key and a nonce to keep it confidential, with an authentication tag that can be used for tamper proofing.
// Encryption: XSalsa20 stream cipher. Authentication: Poly1305 MAC.
TArray<uint8> FUnrealSodiumModule::GenerateKey() {
	TArray<uint8> key;
	key.SetNum(crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(key.GetData());
	return key;
}

int32 FUnrealSodiumModule::EncryptSymmetric(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& key) {
	encrypted.SetNum(data.Num() + crypto_secretbox_MACBYTES);
	return crypto_secretbox_easy(encrypted.GetData(), data.GetData(), data.Num(), nonce.GetData(), key.GetData());
}

int32 FUnrealSodiumModule::DecryptSymmetric(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& key) {
	decrypted.SetNum(decrypted.Num() - crypto_secretbox_MACBYTES);
	return crypto_secretbox_open_easy(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), nonce.GetData(), key.GetData());
}

// Block ciphers
// AES-GCM
// Encrypts a message with a key and a nonce to keep it confidential, with an authentication tag that can be used for tamper proofing.
// Encryption & Authentication: AES-GCM
int32 FUnrealSodiumModule::GenerateAES256GCMKey(TArray<uint8>& generatedKey) {
	if (crypto_aead_aes256gcm_is_available() == 0) {
		// hardware accelerated CM is not available
		generatedKey = TArray<uint8>();
		return -1;
	}
	TArray<uint8> key;
	key.SetNum(crypto_aead_aes256gcm_KEYBYTES);
	crypto_aead_aes256gcm_keygen(key.GetData());
	generatedKey = key;
	return 0;
}

// Generates a nonce
int32 FUnrealSodiumModule::GenerateAES256GCMNonce(TArray<uint8>& generatedNonce) {
	TArray<uint8> nonce;
	nonce.SetNum(crypto_aead_aes256gcm_NPUBBYTES);
	randombytes_buf(nonce.GetData(), sizeof nonce);
	generatedNonce = nonce;
	return 0;
}

// Encrypt data with AES256-gcm
int32 FUnrealSodiumModule::EncryptAES256GCM(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& key) {
	// check nonce size
	if (nonce.Num() != crypto_aead_aes256gcm_NPUBBYTES) { 
		return -1;
	}
	encrypted.SetNum(data.Num() + crypto_aead_aes256gcm_ABYTES);
	return crypto_aead_aes256gcm_encrypt(encrypted.GetData(), nullptr, data.GetData(), data.Num(), nullptr, 0, nullptr, nonce.GetData(), key.GetData());
}

// Decrypt data with AES256-gcm
int32 FUnrealSodiumModule::DecryptAES256GCM(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& key) {
	// check nonce size
	if (nonce.Num() != crypto_aead_aes256gcm_NPUBBYTES) {
		return -1;
	}
	decrypted.SetNum(encrypted.Num() - crypto_aead_aes256gcm_ABYTES);
	return crypto_aead_aes256gcm_decrypt(decrypted.GetData(), nullptr, nullptr, encrypted.GetData(), encrypted.Num(), nullptr, 0, nonce.GetData(), key.GetData());
}

// Derive shared secret from two sets of keys, only knowing their public key
int32 FUnrealSodiumModule::DeriveX25519SharedSecret(TArray<uint8>& theirPublicKey, TArray<uint8>& myPublicKey, TArray<uint8>& myPrivateKey, TArray<uint8>& sharedSecret) {
	// set num to crypto_scalarmult_BYTES of the shared secret, then derive it from myPrivateKey and theirPublicKey
	sharedSecret.SetNum(crypto_scalarmult_BYTES);
	if (crypto_scalarmult(sharedSecret.GetData(), myPrivateKey.GetData(), theirPublicKey.GetData()) != 0) {
		return -1;
	}
	return 0;
}

/*
* Create a temporary derived X25519 shared secret, then create a sha256 hash of (derivedSharedSecret + pk_A + pk_B) 
* where pk_A is the smallest of the two public keys and pk_B is the largest of the two public keys (to ensure that the same hash is generated on both sides).
*/
int32 FUnrealSodiumModule::DeriveX25519Sha256HashedSharedSecret(TArray<uint8>& theirPublicKey, TArray<uint8>& myPublicKey, TArray<uint8>& myPrivateKey, TArray<uint8>& sharedSecret) {
	TArray<uint8> derivedSharedSecret;
	derivedSharedSecret.SetNum(crypto_scalarmult_BYTES);
	if (crypto_scalarmult(derivedSharedSecret.GetData(), myPrivateKey.GetData(), theirPublicKey.GetData()) != 0) {
		return -1;
	}

	// Sort the public keys so that the smallest is first
	TArray<uint8> pk_A = myPublicKey;
	TArray<uint8> pk_B = theirPublicKey;

	if (sodium_compare(myPublicKey.GetData(), theirPublicKey.GetData(), pk_A.Num()) > 0) {
		pk_A = theirPublicKey;
		pk_B = myPublicKey;
	}

	// Create a temporary buffer to hold the data to hash
	TArray<uint8> dataToHash;
	dataToHash.SetNum(crypto_scalarmult_BYTES + pk_A.Num() + pk_B.Num());
	dataToHash.Append(derivedSharedSecret);
	dataToHash.Append(pk_A);
	dataToHash.Append(pk_B);
	
	// Create the resultant shared secret
	TArray<uint8> sha256HashedSharedSecret;
	sha256HashedSharedSecret.SetNum(crypto_hash_sha256_BYTES);

	// Copy the derived shared secret into the dataToHash buffer
	bool shaSuccess = SHA256HashBytes(dataToHash, sha256HashedSharedSecret) != 0;

	// zero out the temporary buffers: sodium_memzero(q, sizeof q);
	sodium_memzero(derivedSharedSecret.GetData(), derivedSharedSecret.Num());
	sodium_memzero(dataToHash.GetData(), dataToHash.Num());

	if (!shaSuccess) {
		return -1;
	}

	sharedSecret = sha256HashedSharedSecret;
	return 0;
}


#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FUnrealSodiumModule, UnrealSodium)
