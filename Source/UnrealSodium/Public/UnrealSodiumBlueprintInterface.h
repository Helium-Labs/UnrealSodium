#pragma once

#include "Kismet/BlueprintFunctionLibrary.h"
#include "Engine.h"
#include "HAL/Platform.h"
#include "GenericPlatform/GenericPlatform.h"
#include "UnrealSodiumBlueprintInterface.generated.h"

UCLASS()
class UUnrealSodiumPluginBPLibrary : public UBlueprintFunctionLibrary
{
	GENERATED_UCLASS_BODY()

public:


	//////////////////////////////////////////////////////////////////////////
	// Utility methods
	//////////////////////////////////////////////////////////////////////////
	
	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Sodium|Utility")
	static TArray<uint8> RandomBytes(int32 len);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static FString ToBase64(TArray<uint8> data);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static FString ToBase64S(FString data);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static TArray<uint8> FromBase64(FString data, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static FString FromBase64S(FString data, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static void ToSha256Hash(TArray<uint8> data, TArray<uint8>& hashedData, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static void ToSha256HashAsB64String(TArray<uint8> data, FString& hashedData, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static void ToSha512Hash(TArray<uint8> data, TArray<uint8>& hashedData, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static void ToSha512HashAsB64String(TArray<uint8> data, FString& hashedData, bool& success);

	//////////////////////////////////////////////////////////////////////////
	// Core functionality
	//////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////////
	// Asymmetric
	//////////////////////////////////////////////////////////////////////////
	// Random X25519 key pair derivation
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& privateKey);

	// Sealed boxes
	// Sealed boxes are designed to anonymously send messages to a recipient given their public key. X25519 and XSalsa20-Poly1305 based.
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptString(FString s, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptString(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, FString& decrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void Encrypt(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void Decrypt(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8>& decrypted, bool& success);

	// Authenticated encryption
	// Encryption relying on a shared secret key that is derived from two sets of keys. Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305.
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptAuthenticated(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptAuthenticated(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success);

	//////////////////////////////////////////////////////////////////////////
	// Symmetric
	//////////////////////////////////////////////////////////////////////////
	// Stream ciphers
	// XSalsa20
	// Encrypts a message with a key and a nonce to keep it confidential, with an authentication tag that can be used for tamper proofing.
	// Encryption: XSalsa20 stream cipher. Authentication: Poly1305 MAC.
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptStringSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptStringSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptSymmetric(TArray<uint8> data, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static TArray<uint8> GenerateKey();

	// Block ciphers
	// AES-GCM
	// Encrypts a message with a key and a nonce to keep it confidential, with an authentication tag that can be used for tamper proofing.
	// Encryption & Authentication: AES-GCM
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void GenerateAES256GCMKey(TArray<uint8>& key, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void GenerateAES256GCMNonce(TArray<uint8>& generatedNonce);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptStringAES256GCMSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptStringAES256GCMSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success);

	// Derives a X25519 shared secret from the a senders public key and the receivers key pair
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DeriveX25519SharedSecret(TArray<uint8> theirPublicKey, TArray<uint8> myPublicKey, TArray<uint8> myPrivateKey, TArray<uint8>& sharedSecret, bool& success);

	// Create a temporary derived X25519 shared secret, then create a sha256 hash of (derivedSharedSecret + pk_A + pk_B)
	// where pk_A is the smallest of the two public keys and pk_B is the largest of the two public keys (to ensure that the same hash is generated on both sides).
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DeriveX25519Sha256HashedSharedSecret(TArray<uint8> theirPublicKey, TArray<uint8> myPublicKey, TArray<uint8> myPrivateKey, TArray<uint8>& sharedSecret, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static TArray<uint8> GenerateSymmetricNonce();

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Sodium|Core")
	static int64 SymmetricNonceLength();

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static TArray<uint8> GenerateAsymmetricNonce();

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Sodium|Core")
	static int64 AsymmetricNonceLength();
};