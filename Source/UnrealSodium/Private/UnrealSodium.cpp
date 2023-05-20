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

int FUnrealSodiumModule::Encrypt(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& publicKey) {
	encrypted.SetNum(data.Num() + crypto_box_SEALBYTES);
	return crypto_box_seal(encrypted.GetData(), data.GetData(), data.Num(), publicKey.GetData());
}

int FUnrealSodiumModule::Decrypt(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	decrypted.SetNum(encrypted.Num() - crypto_box_SEALBYTES);
	return crypto_box_seal_open(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), publicKey.GetData(), privateKey.GetData());
}

int FUnrealSodiumModule::EncryptAuthenticated(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	encrypted.SetNum(data.Num() + crypto_box_MACBYTES);
	return crypto_box_easy(encrypted.GetData(), data.GetData(), data.Num(), nonce.GetData(), publicKey.GetData(), privateKey.GetData());
}

int FUnrealSodiumModule::DecryptAuthenticated(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	decrypted.SetNum(encrypted.Num() - crypto_box_MACBYTES);
	return crypto_box_open_easy(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), nonce.GetData(), publicKey.GetData(), privateKey.GetData());
}

//////////////////////////////////////////////////////////////////////////
// Symmetric
//////////////////////////////////////////////////////////////////////////

TArray<uint8> FUnrealSodiumModule::GenerateKey() {
	TArray<uint8> key;
	key.SetNum(crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(key.GetData());
	return key;
}

int FUnrealSodiumModule::EncryptSymmetric(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& key) {
	encrypted.SetNum(data.Num() + crypto_secretbox_MACBYTES);
	return crypto_secretbox_easy(encrypted.GetData(), data.GetData(), data.Num(), nonce.GetData(), key.GetData());
}

int FUnrealSodiumModule::DecryptSymmetric(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& key) {
	decrypted.SetNum(decrypted.Num() - crypto_secretbox_MACBYTES);
	return crypto_secretbox_open_easy(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), nonce.GetData(), key.GetData());
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FUnrealSodiumModule, UnrealSodium)
