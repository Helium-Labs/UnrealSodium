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


	//////////////////////////////////////////////////////////////////////////
	// Core functionality
	//////////////////////////////////////////////////////////////////////////

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void GenerateKeyPair(TArray<uint8>& publicKey, TArray<uint8>& privateKey);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptString(FString s, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptString(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, FString& decrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void Encrypt(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void Decrypt(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8>& decrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptAuthenticated(TArray<uint8> data, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptAuthenticated(TArray<uint8> encrypted, TArray<uint8> publicKey, TArray<uint8> privateKey, TArray<uint8> nonce, TArray<uint8>& decrypted, bool& success);

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

	// AES256
	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void GenerateAES256GCMKey(TArray<uint8>& key, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void GenerateAES256GCMNonce(TArray<uint8>& generatedNonce);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void EncryptStringAES256GCMSymmetric(FString s, TArray<uint8> key, TArray<uint8> nonce, TArray<uint8>& encrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Core")
	static void DecryptStringAES256GCMSymmetric(TArray<uint8> encrypted, TArray<uint8> key, TArray<uint8> nonce, FString& decrypted, bool& success);

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static TArray<uint8> GenerateSymmetricNonce();

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Sodium|Core")
	static int64 SymmetricNonceLength();

	UFUNCTION(BlueprintCallable, Category = "Sodium|Utility")
	static TArray<uint8> GenerateAsymmetricNonce();

	UFUNCTION(BlueprintCallable, BlueprintPure, Category = "Sodium|Core")
	static int64 AsymmetricNonceLength();
};