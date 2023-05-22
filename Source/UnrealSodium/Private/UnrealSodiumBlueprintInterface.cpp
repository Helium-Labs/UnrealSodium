#include "UnrealSodiumBlueprintInterface.h"
#include "UnrealSodiumPrivatePCH.h"
#include "UnrealSodium.h"
#include "Misc/Base64.h"

UUnrealSodiumPluginBPLibrary::UUnrealSodiumPluginBPLibrary(const FObjectInitializer& ObjectInitializer) : Super(ObjectInitializer){
}

bool SanityCheckPass(TArray<uint8> &key){
	return (key.Num() > 0);
}

TArray<uint8> UUnrealSodiumPluginBPLibrary::RandomBytes(int32 len){
	TArray<uint8> ret;
	ret.SetNum(len);
	FUnrealSodiumModule::Get().RandomBytes(ret.GetData(), len);
	return ret;
}

void UUnrealSodiumPluginBPLibrary::GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& privateKey) {
	FUnrealSodiumModule::Get().GenerateKeyPair(publicKey, privateKey);
}

void UUnrealSodiumPluginBPLibrary::EncryptString(FString s, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(publicKey)){
		success = false;
		return;
	}

	auto sodium = FUnrealSodiumModule::Get();

	TArray<uint8> data;
	FTCHARToUTF8 Convert(*s);
	data.Append((uint8*)Convert.Get(), Convert.Length());
	encrypted.SetNum(Convert.Length() + sodium.GetBoxSealBytes());

	auto msg = sodium.Encrypt(encrypted, data, publicKey);

	if (msg == -1) {
		encrypted.Empty();
		success = false;
	} else {
		success = true;
	}
}

void UUnrealSodiumPluginBPLibrary::DecryptString(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, FString& decrypted, bool& success) {
  if (!SanityCheckPass(encrypted) || !SanityCheckPass(publicKey) || !SanityCheckPass(privateKey)){
		success = false;
		return;
	}
  
	auto sodium = FUnrealSodiumModule::Get();

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

FString UUnrealSodiumPluginBPLibrary::ToBase64(TArray<uint8> data) {
	return FBase64::Encode(data);
}

FString UUnrealSodiumPluginBPLibrary::ToBase64S(FString data) {
	return FBase64::Encode(data);
}

TArray<uint8> UUnrealSodiumPluginBPLibrary::FromBase64(FString data, bool& success) {
	TArray<uint8> dest;
	success = FBase64::Decode(data, dest);
	return dest;
}

FString UUnrealSodiumPluginBPLibrary::FromBase64S(FString data, bool& success) {
	FString dest;
	success = FBase64::Decode(data, dest);
	return dest;
}

void UUnrealSodiumPluginBPLibrary::ToSha256Hash(TArray<uint8> data, TArray<uint8>& hashedData, bool& success) {
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.SHA256HashBytes(data, hashedData) == 0;
}

void UUnrealSodiumPluginBPLibrary::ToSha256HashAsB64String(TArray<uint8> data, FString& hashedData, bool& success) {
	auto sodium = FUnrealSodiumModule::Get();
	TArray<uint8> hashedDataBytes;
	success = sodium.SHA256HashBytes(data, hashedDataBytes) == 0;
	hashedData = FBase64::Encode(hashedDataBytes);
}

void UUnrealSodiumPluginBPLibrary::ToSha512Hash(TArray<uint8> data, TArray<uint8>& hashedData, bool& success) {
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.SHA512HashBytes(data, hashedData) == 0;
}

void UUnrealSodiumPluginBPLibrary::ToSha512HashAsB64String(TArray<uint8> data, FString& hashedData, bool& success) {
	auto sodium = FUnrealSodiumModule::Get();
	TArray<uint8> hashedDataBytes;
	success = sodium.SHA512HashBytes(data, hashedDataBytes) == 0;
	hashedData = FBase64::Encode(hashedDataBytes);
}

void UUnrealSodiumPluginBPLibrary::Encrypt(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(publicKey)){
		success = false;
		return;
	}
  
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.Encrypt(encrypted, data, publicKey) == 0;
}

void UUnrealSodiumPluginBPLibrary::Decrypt(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8>& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(publicKey) || !SanityCheckPass(privateKey)) {
		success = false;
		return;
	}
  
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.Decrypt(decrypted, encrypted, publicKey, privateKey) == 0;
}

void UUnrealSodiumPluginBPLibrary::EncryptAuthenticated(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(publicKey)){
		success = false;
		return;
	}
  
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.EncryptAuthenticated(encrypted, data, nonce, publicKey, privateKey) == 0;
}

void UUnrealSodiumPluginBPLibrary::DecryptAuthenticated(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(publicKey) || !SanityCheckPass(privateKey)) {
		success = false;
		return;
	}
  
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.DecryptAuthenticated(decrypted, encrypted, nonce, publicKey, privateKey) == 0;
}

void UUnrealSodiumPluginBPLibrary::EncryptSymmetric(TArray<uint8> data, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(data) || !SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.EncryptSymmetric(encrypted, data, nonce, key) == 0;
}

void UUnrealSodiumPluginBPLibrary::DecryptSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.DecryptSymmetric(decrypted, encrypted, nonce, key) == 0;
}

TArray<uint8> UUnrealSodiumPluginBPLibrary::GenerateKey() {
	return FUnrealSodiumModule::Get().GenerateKey();
}

void UUnrealSodiumPluginBPLibrary::GenerateAES256GCMKey(TArray<uint8>& key, bool& success)
{
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.GenerateAES256GCMKey(key) == 0;
}

void UUnrealSodiumPluginBPLibrary::GenerateAES256GCMNonce(TArray<uint8>& generatedNonce)
{
	auto sodium = FUnrealSodiumModule::Get();
	sodium.GenerateAES256GCMNonce(generatedNonce);
}

void UUnrealSodiumPluginBPLibrary::EncryptStringAES256GCMSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success)
{
	auto sodium = FUnrealSodiumModule::Get();

	TArray<uint8> data;
	FTCHARToUTF8 Convert(*s);
	data.Append((uint8*)Convert.Get(), Convert.Length());

	success = sodium.EncryptAES256GCM(encrypted, data, nonce, key) == 0;
}

void UUnrealSodiumPluginBPLibrary::DecryptStringAES256GCMSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success)
{
	auto sodium = FUnrealSodiumModule::Get();
	TArray<uint8> data;
	success = sodium.DecryptAES256GCM(data, encrypted, nonce, key) == 0;
	if (success) {
		decrypted = FString(UTF8_TO_TCHAR(data.GetData()));
	}
	else {
		decrypted = FString();
	}
}

void UUnrealSodiumPluginBPLibrary::DeriveX25519SharedSecret(TArray<uint8> theirPublicKey, TArray<uint8> myPublicKey, TArray<uint8> myPrivateKey, TArray<uint8>& sharedSecret, bool& success) {
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.DeriveX25519SharedSecret(sharedSecret, theirPublicKey, myPublicKey, myPrivateKey) == 0;
}

void UUnrealSodiumPluginBPLibrary::DeriveX25519Sha256HashedSharedSecret(TArray<uint8> theirPublicKey, TArray<uint8> myPublicKey, TArray<uint8> myPrivateKey, TArray<uint8>& sharedSecret, bool& success) {
	auto sodium = FUnrealSodiumModule::Get();
	success = sodium.DeriveX25519Sha256HashedSharedSecret(sharedSecret, theirPublicKey, myPublicKey, myPrivateKey) == 0;
}

void UUnrealSodiumPluginBPLibrary::EncryptStringSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success) {
	if (!SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FUnrealSodiumModule::Get();

	TArray<uint8> data;
	FTCHARToUTF8 Convert(*s);
	data.Append((uint8*)Convert.Get(), Convert.Length());
	encrypted.SetNum(Convert.Length() + sodium.GetMacBytesSymmetric());

	auto msg = sodium.EncryptSymmetric(encrypted, data, nonce, key);

	if (msg == -1) {
		encrypted.Empty();
		success = false;
	}
	else {
		success = true;
	}
}

void UUnrealSodiumPluginBPLibrary::DecryptStringSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success) {
	if (!SanityCheckPass(encrypted) || !SanityCheckPass(key)) {
		success = false;
		return;
	}

	auto sodium = FUnrealSodiumModule::Get();

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

int64 UUnrealSodiumPluginBPLibrary::AsymmetricNonceLength() {
	return FUnrealSodiumModule::Get().GetAssymetricNonceLen();
}

int64 UUnrealSodiumPluginBPLibrary::SymmetricNonceLength() {
	return FUnrealSodiumModule::Get().GetSymmetricNonceLen();
}

TArray<uint8> UUnrealSodiumPluginBPLibrary::GenerateAsymmetricNonce() {
	auto sodium = FUnrealSodiumModule::Get();

	TArray<uint8> nonce;
	auto len = sodium.GetAssymetricNonceLen();
	nonce.SetNum(len);

	sodium.RandomBytes(nonce.GetData(), len);

	return nonce;
}

TArray<uint8> UUnrealSodiumPluginBPLibrary::GenerateSymmetricNonce() {

	auto sodium = FUnrealSodiumModule::Get();

	TArray<uint8> nonce;
	auto len = sodium.GetSymmetricNonceLen();
	nonce.SetNum(len);

	sodium.RandomBytes(nonce.GetData(), len);

	return nonce;
}