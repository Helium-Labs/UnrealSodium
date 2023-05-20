// Copyright 1998-2016 Epic Games, Inc. All Rights Reserved.

//#include <vector>
#include "SodiumUE5.h"
#include "SodiumUE5PrivatePCH.h"
#include "Core.h"
#include "Interfaces/IPluginManager.h"


#if PLATFORM_WINDOWS
//#include "../../ThirdParty/SodiumUE5Library/SodiumUE5.h"
#endif // PLATFORM_WINDOWS

#define LOCTEXT_NAMESPACE "FSodiumUE5Module"

void FSodiumUE5Module::StartupModule()
{
	sodium_init();
}

void FSodiumUE5Module::ShutdownModule()
{
}

//////////////////////////////////////////////////////////////////////////
// Sodium API
//////////////////////////////////////////////////////////////////////////

void FSodiumUE5Module::GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& secretKey) {
	auto sodium = FSodiumUE5Module::Get();

	// allocate space for key
	publicKey.SetNum(sodium.GetPublicKeyBytes());
	secretKey.SetNum(sodium.GetSecretKeyBytes());

	// generate key
	crypto_box_keypair(publicKey.GetData(), secretKey.GetData());
}

void FSodiumUE5Module::RandomBytes(unsigned char* bytes, size_t len) {
	randombytes_buf(bytes, len);
}

//////////////////////////////////////////////////////////////////////////
// Asymmetric
//////////////////////////////////////////////////////////////////////////

int FSodiumUE5Module::Encrypt(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& publicKey) {
	encrypted.SetNum(data.Num() + crypto_box_SEALBYTES);
	return crypto_box_seal(encrypted.GetData(), data.GetData(), data.Num(), publicKey.GetData());
}

int FSodiumUE5Module::Decrypt(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	decrypted.SetNum(encrypted.Num() - crypto_box_SEALBYTES);
	return crypto_box_seal_open(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), publicKey.GetData(), privateKey.GetData());
}

int FSodiumUE5Module::EncryptAuthenticated(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	encrypted.SetNum(data.Num() + crypto_box_MACBYTES);
	return crypto_box_easy(encrypted.GetData(), data.GetData(), data.Num(), nonce.GetData(), publicKey.GetData(), privateKey.GetData());
}

int FSodiumUE5Module::DecryptAuthenticated(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	decrypted.SetNum(encrypted.Num() - crypto_box_MACBYTES);
	return crypto_box_open_easy(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), nonce.GetData(), publicKey.GetData(), privateKey.GetData());
}

//////////////////////////////////////////////////////////////////////////
// Symmetric
//////////////////////////////////////////////////////////////////////////

TArray<uint8> FSodiumUE5Module::GenerateKey() {
	TArray<uint8> key;
	key.SetNum(crypto_secretbox_KEYBYTES);
	crypto_secretbox_keygen(key.GetData());
	return key;
}

int FSodiumUE5Module::EncryptSymmetric(TArray<uint8>& encrypted, TArray<uint8>& data, TArray<uint8>& nonce, TArray<uint8>& key) {
	encrypted.SetNum(data.Num() + crypto_secretbox_MACBYTES);
	return crypto_secretbox_easy(encrypted.GetData(), data.GetData(), data.Num(), nonce.GetData(), key.GetData());
}

int FSodiumUE5Module::DecryptSymmetric(TArray<uint8>& decrypted, TArray<uint8>& encrypted, TArray<uint8>& nonce, TArray<uint8>& key) {
	decrypted.SetNum(decrypted.Num() - crypto_secretbox_MACBYTES);
	return crypto_secretbox_open_easy(decrypted.GetData(), encrypted.GetData(), encrypted.Num(), nonce.GetData(), key.GetData());
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FSodiumUE5Module, SodiumUE5)
