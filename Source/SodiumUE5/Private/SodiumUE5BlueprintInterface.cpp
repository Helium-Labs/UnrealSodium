#include "SodiumUE5BlueprintInterface.h"
#include "SodiumUE5PrivatePCH.h"
#include "SodiumUE5.h"
#include "Misc/Base64.h"
#include <string> 

USodiumUE5PluginBPLibrary::USodiumUE5PluginBPLibrary(const FObjectInitializer& ObjectInitializer) : Super(ObjectInitializer){
}

bool SanityCheckPass(TArray<uint8> &key){
	return (key.Num() > 0);
}

TArray<uint8> USodiumUE5PluginBPLibrary::RandomBytes(int32 len){
	TArray<uint8> ret;
	ret.SetNum(len);
	FSodiumUE5Module::Get().RandomBytes(ret.GetData(), len);
	return ret;
}

void USodiumUE5PluginBPLibrary::GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	FSodiumUE5Module::Get().GenerateKeyPair(publicKey, privateKey);
}

void USodiumUE5PluginBPLibrary::EncryptString(FString s, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(publicKey)){
		success = false;
		return;
	}

	auto sodium = FSodiumUE5Module::Get();

	TArray<uint8> data;
	std::string _s(TCHAR_TO_UTF8(*s));
	data.Append((unsigned char *)_s.data(), _s.size());
	encrypted.SetNum(_s.size() + sodium.GetBoxSealBytes());

	auto msg = sodium.Encrypt(encrypted, data, publicKey);

	if (msg == -1) {
		encrypted.Empty();
		success = false;
	} else {
		success = true;
	}
}

void USodiumUE5PluginBPLibrary::DecryptString(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, FString& decrypted, bool& success) {
  if (!SanityCheckPass(encrypted) || !SanityCheckPass(publicKey) || !SanityCheckPass(privateKey)){
		success = false;
		return;
	}
  
	auto sodium = FSodiumUE5Module::Get();

	auto decryptedContainerSize = encrypted.Num() + sodium.GetBoxSealBytes();

	TArray<uint8> _decrypted;

	// preemptively terminate the string
	_decrypted.SetNumZeroed(decryptedContainerSize + 1);

	auto msg = sodium.Decrypt(_decrypted, encrypted, publicKey, privateKey);
	
	if(msg == -1){
		success = false;
	} else {
		decrypted = FString(UTF8_TO_TCHAR(_decrypted.GetData()));
		success = true;
	}
}

FString USodiumUE5PluginBPLibrary::ToBase64(TArray<uint8> data) {
	return FBase64::Encode(data);
}

FString USodiumUE5PluginBPLibrary::ToBase64S(FString data) {
	return FBase64::Encode(data);
}

TArray<uint8> USodiumUE5PluginBPLibrary::FromBase64(FString data, bool& success) {
	TArray<uint8> dest;
	success = FBase64::Decode(data, dest);
	return dest;
}

FString USodiumUE5PluginBPLibrary::FromBase64S(FString data, bool& success) {
	FString dest;
	success = FBase64::Decode(data, dest);
	return dest;
}

void USodiumUE5PluginBPLibrary::Encrypt(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(publicKey)){
		success = false;
		return;
	}
  
	auto sodium = FSodiumUE5Module::Get();
	success = sodium.Encrypt(encrypted, data, publicKey) == 0 ? true : false;
}

void USodiumUE5PluginBPLibrary::Decrypt(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8>& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(publicKey) || !SanityCheckPass(privateKey)) {
		success = false;
		return;
	}
  
	auto sodium = FSodiumUE5Module::Get();
	success = sodium.Decrypt(decrypted, encrypted, publicKey, privateKey) == 0 ? true : false;
}

void USodiumUE5PluginBPLibrary::EncryptAuthenticated(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(publicKey)){
		success = false;
		return;
	}
  
	auto sodium = FSodiumUE5Module::Get();
	success = sodium.EncryptAuthenticated(encrypted, data, nonce, publicKey, privateKey) == 0 ? true : false;
}

void USodiumUE5PluginBPLibrary::DecryptAuthenticated(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(publicKey) || !SanityCheckPass(privateKey)) {
		success = false;
		return;
	}
  
	auto sodium = FSodiumUE5Module::Get();
	success = sodium.DecryptAuthenticated(decrypted, encrypted, nonce, publicKey, privateKey) == 0 ? true : false;
}

void USodiumUE5PluginBPLibrary::EncryptSymmetric(TArray<uint8> data, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(data) || !SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FSodiumUE5Module::Get();
	success = (sodium.EncryptSymmetric(encrypted, data, nonce, key) > 0);
}

void USodiumUE5PluginBPLibrary::DecryptSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FSodiumUE5Module::Get();
	success = (sodium.DecryptSymmetric(decrypted, encrypted, nonce, key) > 0);
}

TArray<uint8> USodiumUE5PluginBPLibrary::GenerateKey() {
	return FSodiumUE5Module::Get().GenerateKey();
}

void USodiumUE5PluginBPLibrary::EncryptStringSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FSodiumUE5Module::Get();

	TArray<uint8> data;
	std::string _s(TCHAR_TO_UTF8(*s));
	data.Append((unsigned char *)_s.data(), _s.size());
	encrypted.SetNum(_s.size() + sodium.GetMacBytesSymmetric());

	auto msg = sodium.EncryptSymmetric(encrypted, data, nonce, key);

	if (msg == -1) {
		encrypted.Empty();
		success = false;
	} else {
		success = true;
	}
}

void USodiumUE5PluginBPLibrary::DecryptStringSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FSodiumUE5Module::Get();

	auto decryptedContainerSize = encrypted.Num() + sodium.GetMacBytesSymmetric();

	TArray<uint8> _decrypted;

	// preemptively terminate the string
	_decrypted.SetNumZeroed(decryptedContainerSize + 1);

	auto msg = sodium.DecryptSymmetric(_decrypted, encrypted, nonce, key);

	if (msg == -1) {
		success = false;
	} else {
		decrypted = FString(UTF8_TO_TCHAR(_decrypted.GetData()));
		success = true;
	}
}

int USodiumUE5PluginBPLibrary::AsymmetricNonceLength() {
	return FSodiumUE5Module::Get().GetAssymetricNonceLen();
}

int USodiumUE5PluginBPLibrary::SymmetricNonceLength() {
	return FSodiumUE5Module::Get().GetSymmetricNonceLen();
}

TArray<uint8> USodiumUE5PluginBPLibrary::GenerateAsymmetricNonce() {
	auto sodium = FSodiumUE5Module::Get();

	TArray<uint8> nonce;
	auto len = sodium.GetAssymetricNonceLen();
	nonce.SetNum(len);

	sodium.RandomBytes(nonce.GetData(), len);

	return nonce;
}

TArray<uint8> USodiumUE5PluginBPLibrary::GenerateSymmetricNonce() {

	auto sodium = FSodiumUE5Module::Get();

	TArray<uint8> nonce;
	auto len = sodium.GetSymmetricNonceLen();
	nonce.SetNum(len);

	sodium.RandomBytes(nonce.GetData(), len);

	return nonce;
}