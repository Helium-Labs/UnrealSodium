// Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

using UnrealBuildTool;
using System.IO;

public class UnrealSodium : ModuleRules
{
    public UnrealSodium(ReadOnlyTargetRules Target) : base(Target)
	{
        /*
        string sodiumUnrealHeaders = Path.Combine(ModuleDirectory, "./Public/");

        PublicIncludePaths.AddRange(
			new string[] {
                sodiumUnrealHeaders,
                sodiumIncludes
			}
		);

        string sodiumUnrealDefinitions = Path.Combine(ModuleDirectory, "./Private/");
        PrivateIncludePaths.AddRange(new string[] {
            sodiumUnrealDefinitions
        });
        */

        PublicDefinitions.Add("SODIUM_STATIC=1");
        PublicDefinitions.Add("SODIUM_EXPORT=");

        PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;
        string sodiumIncludes = Path.Combine(ModuleDirectory, "../ThirdParty/libsodium/");

        PublicIncludePaths.AddRange(
            new string[] {
                sodiumIncludes
				// ... add public include paths required here ...
			}
            );


        PrivateIncludePaths.AddRange(
            new string[] {
				// ... add other private include paths required here ...
			}
            );


        PublicDependencyModuleNames.AddRange(
            new string[]
            {
                "Core"
				// ... add other public dependencies that you statically link with here ...
			}
            );


        PrivateDependencyModuleNames.AddRange(
            new string[]
            {
                "CoreUObject",
                "Engine",
                "Slate",
                "SlateCore",
                "Projects"
				// ... add private dependencies that you statically link with here ...	
			}
            );


        DynamicallyLoadedModuleNames.AddRange(
            new string[]
            {
				// ... add any modules that your module loads dynamically here ...
			}
            );

        string PlatformString = (Target.Platform == UnrealTargetPlatform.Win64) ? "x64" : "Win32";
        string path = Path.Combine(ModuleDirectory, "../ThirdParty/libsodium/Build/Release/" + PlatformString + "/libsodium.lib");
        PublicAdditionalLibraries.Add(path);
    }
}
