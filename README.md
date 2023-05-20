![UnrealSodium](https://raw.githubusercontent.com/helium-labs/UnrealSodium/master/logo.png)
============

An easy to use public and private cryptography plugin for Unreal Engine 5 based on libsodium.

It currently works only on Win64 builds of UE5. Support for Android, iOS, Linux and MacOS are planned, but not guaranteed to happen. The plugin is very simple due to the portable nature of libsodium and it is compatible with most versions of UE5.

Last tested on: **5.1.0**

## Installation

1. *git clone --recursive* this repository to your UnrealProject/Plugins/ folder.
2. In the Source\ThirdParty\libsodium\libsodium.sln, change the Visual Studio platform toolset to v142 to match the Unreal Engine 5 VS configuration and then compile it. This step will generate the sodium library. Use x64 and Release options as target.
3. Regenerate code for your UE5 project (right click YourGame.uproject to do it)
4. Add "UnrealSodium" to YourGame.Build.cs in PublicDependencyModuleNames.
5. Open and Build your game in Visual Studio.
6. Start the editor as usual, allow it to compile UnrealSodium, this should only happen once.
7. Build/Package your game as you normally would.

Contributions are warmly welcomed to further enhance the compatibility and usability of Unreal Engine Sodium with UE5. 

# Usage

![Public encryption](http://i.imgur.com/ezgBj7v.jpg)

# What exactly is the Libsodium Cryptography Library?

![libsodium](https://raw.github.com/jedisct1/libsodium/master/logo.png)

Libsodium is a modern, versatile software library designed for encryption, decryption, signatures, password hashing, and more.

Originating as a fork of [NaCl](http://nacl.cr.yp.to/), it offers a compatible API and additional enhancements to further improve usability. Its goal is to offer core operations essential for the development of higher-level cryptographic tools.

One of Libsodium's strengths is its portability. It is cross-compilable and supports a wide array of compilers and operating systems, including Windows (MingW or Visual Studio, x86 and x64), iOS, Android, along with Javascript and Webassembly compatibility.

## Documentation
You can access the official documentation [here](https://doc.libsodium.org), which is maintained on Gitbook and built from the [libsodium-doc](https://github.com/jedisct1/libsodium-doc) repository.

## Integrity Checking
Detailed integrity checking instructions, including the signing key for Libsodium, can be found in the [installation](https://download.libsodium.org/doc/installation#integrity-checking) section of the documentation.


# License
https://opensource.org/licenses/MIT

## libsodium license:
https://opensource.org/licenses/ISC

# Tags

libsodium, encryption, cryptography, UnrealEngine, UnrealEngine5, UE5, UnrealSodium, libsodium-ue5, game-development, encryption-library, game-engine, game-plugin
