#include "UnrealSodium.h"
#include "UnrealSodiumPrivatePCH.h"
#include "Core.h"
#include "Interfaces/IPluginManager.h"


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

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FUnrealSodiumModule, UnrealSodium)
