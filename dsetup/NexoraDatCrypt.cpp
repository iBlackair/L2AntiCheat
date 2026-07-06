#define WIN32_LEAN_AND_MEAN
#include "NexoraDatCrypt.h"

#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>

#pragma comment(lib, "Bcrypt.lib")

namespace NexoraDatCrypt
{
namespace
{
    const unsigned char kMagic[16] = {
        'N', 'E', 'X', 'O', 'R', 'A', 'D', 'A',
        'T', 'P', 'R', 'O', 'T', '1', '\r', '\n'
    };
    const DWORD kVersion = 1;
    const size_t kIvSize = 16;
    const size_t kTagSize = 32;

#pragma pack(push, 1)
    struct ProtectedHeader
    {
        unsigned char magic[16];
        DWORD version;
        DWORD headerSize;
        unsigned long long plainSize;
        unsigned char iv[kIvSize];
        unsigned char tag[kTagSize];
    };
#pragma pack(pop)

    struct AlgHandle
    {
        BCRYPT_ALG_HANDLE handle;
        AlgHandle() : handle(NULL) {}
        ~AlgHandle() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
    };

    struct HashHandle
    {
        BCRYPT_HASH_HANDLE handle;
        HashHandle() : handle(NULL) {}
        ~HashHandle() { if (handle) BCryptDestroyHash(handle); }
    };

    struct KeyHandle
    {
        BCRYPT_KEY_HANDLE handle;
        KeyHandle() : handle(NULL) {}
        ~KeyHandle() { if (handle) BCryptDestroyKey(handle); }
    };

    static std::wstring StatusError(const wchar_t* operation, NTSTATUS status)
    {
        wchar_t buffer[128] = {};
        swprintf_s(buffer, L"%s falhou: 0x%08X", operation, static_cast<unsigned int>(status));
        return buffer;
    }

    static bool ReadFileBytes(const wchar_t* file, std::vector<unsigned char>& bytes)
    {
        std::ifstream input(file, std::ios::binary);
        if (!input)
            return false;

        bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        return true;
    }

    static bool WriteFileBytes(const wchar_t* file, const std::vector<unsigned char>& bytes)
    {
        std::ofstream output(file, std::ios::binary | std::ios::trunc);
        if (!output)
            return false;

        if (!bytes.empty())
            output.write(reinterpret_cast<const char*>(&bytes[0]), static_cast<std::streamsize>(bytes.size()));

        return static_cast<bool>(output);
    }

    static bool Sha256(const unsigned char* data, size_t size, std::vector<unsigned char>& digest, std::wstring& error)
    {
        AlgHandle alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg.handle, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptOpenAlgorithmProvider(SHA256)", status);
            return false;
        }

        DWORD objectLength = 0;
        DWORD result = 0;
        status = BCryptGetProperty(alg.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &result, 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptGetProperty(SHA256)", status);
            return false;
        }

        std::vector<unsigned char> object(objectLength);
        HashHandle hash;
        status = BCryptCreateHash(alg.handle, &hash.handle, &object[0], objectLength, NULL, 0, 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptCreateHash(SHA256)", status);
            return false;
        }

        if (size > 0)
        {
            status = BCryptHashData(hash.handle, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0);
            if (status < 0)
            {
                error = StatusError(L"BCryptHashData(SHA256)", status);
                return false;
            }
        }

        digest.assign(32, 0);
        status = BCryptFinishHash(hash.handle, &digest[0], static_cast<ULONG>(digest.size()), 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptFinishHash(SHA256)", status);
            return false;
        }
        return true;
    }

    static bool DeriveKey(const char* purpose, std::vector<unsigned char>& key, std::wstring& error)
    {
        const unsigned char seed[] = {
            0x9E, 0x27, 0x61, 0x40, 0xB4, 0x73, 0xA8, 0x1D,
            0x54, 0xC0, 0x11, 0xE8, 0x7A, 0x32, 0xF5, 0x90,
            0x2D, 0x45, 0x88, 0xC1, 0xF3, 0x18, 0x6B, 0x0E,
            0xD9, 0xAA, 0x74, 0x5C, 0x03, 0xE1, 0xBC, 0x6F
        };
        const char prefix[] = "Nexora.DatProtect.v1.";

        std::vector<unsigned char> material;
        material.insert(material.end(), seed, seed + sizeof(seed));
        material.insert(material.end(), prefix, prefix + sizeof(prefix) - 1);
        material.insert(material.end(), purpose, purpose + strlen(purpose));
        return Sha256(material.empty() ? NULL : &material[0], material.size(), key, error);
    }

    static std::vector<unsigned char> HeaderBytesWithZeroTag(const ProtectedHeader& header)
    {
        ProtectedHeader copy = header;
        ZeroMemory(copy.tag, sizeof(copy.tag));
        const unsigned char* begin = reinterpret_cast<const unsigned char*>(&copy);
        return std::vector<unsigned char>(begin, begin + sizeof(copy));
    }

    static bool HmacSha256(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& first,
        const std::vector<unsigned char>& second,
        std::vector<unsigned char>& digest,
        std::wstring& error)
    {
        AlgHandle alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg.handle, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status < 0)
        {
            error = StatusError(L"BCryptOpenAlgorithmProvider(HMAC)", status);
            return false;
        }

        DWORD objectLength = 0;
        DWORD result = 0;
        status = BCryptGetProperty(alg.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &result, 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptGetProperty(HMAC)", status);
            return false;
        }

        std::vector<unsigned char> object(objectLength);
        HashHandle hash;
        status = BCryptCreateHash(
            alg.handle,
            &hash.handle,
            &object[0],
            objectLength,
            const_cast<PUCHAR>(&key[0]),
            static_cast<ULONG>(key.size()),
            0);
        if (status < 0)
        {
            error = StatusError(L"BCryptCreateHash(HMAC)", status);
            return false;
        }

        if (!first.empty())
        {
            status = BCryptHashData(hash.handle, const_cast<PUCHAR>(&first[0]), static_cast<ULONG>(first.size()), 0);
            if (status < 0)
            {
                error = StatusError(L"BCryptHashData(HMAC/header)", status);
                return false;
            }
        }

        if (!second.empty())
        {
            status = BCryptHashData(hash.handle, const_cast<PUCHAR>(&second[0]), static_cast<ULONG>(second.size()), 0);
            if (status < 0)
            {
                error = StatusError(L"BCryptHashData(HMAC/data)", status);
                return false;
            }
        }

        digest.assign(kTagSize, 0);
        status = BCryptFinishHash(hash.handle, &digest[0], static_cast<ULONG>(digest.size()), 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptFinishHash(HMAC)", status);
            return false;
        }
        return true;
    }

    static bool FixedTimeEquals(const unsigned char* left, const unsigned char* right, size_t size)
    {
        unsigned char diff = 0;
        for (size_t i = 0; i < size; ++i)
            diff |= left[i] ^ right[i];
        return diff == 0;
    }

    static bool AesDecrypt(
        const std::vector<unsigned char>& input,
        const std::vector<unsigned char>& key,
        const unsigned char* iv,
        std::vector<unsigned char>& output,
        std::wstring& error)
    {
        AlgHandle alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg.handle, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptOpenAlgorithmProvider(AES)", status);
            return false;
        }

        status = BCryptSetProperty(
            alg.handle,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)),
            0);
        if (status < 0)
        {
            error = StatusError(L"BCryptSetProperty(AES/CBC)", status);
            return false;
        }

        DWORD objectLength = 0;
        DWORD result = 0;
        status = BCryptGetProperty(alg.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &result, 0);
        if (status < 0)
        {
            error = StatusError(L"BCryptGetProperty(AES)", status);
            return false;
        }

        std::vector<unsigned char> object(objectLength);
        KeyHandle aesKey;
        status = BCryptGenerateSymmetricKey(
            alg.handle,
            &aesKey.handle,
            &object[0],
            objectLength,
            const_cast<PUCHAR>(&key[0]),
            static_cast<ULONG>(key.size()),
            0);
        if (status < 0)
        {
            error = StatusError(L"BCryptGenerateSymmetricKey(AES)", status);
            return false;
        }

        std::vector<unsigned char> ivCopy(iv, iv + kIvSize);
        ULONG outputSize = 0;
        status = BCryptDecrypt(
            aesKey.handle,
            const_cast<PUCHAR>(&input[0]),
            static_cast<ULONG>(input.size()),
            NULL,
            &ivCopy[0],
            static_cast<ULONG>(ivCopy.size()),
            NULL,
            0,
            &outputSize,
            BCRYPT_BLOCK_PADDING);
        if (status < 0)
        {
            error = StatusError(L"BCryptDecrypt(size)", status);
            return false;
        }

        output.assign(outputSize, 0);
        ivCopy.assign(iv, iv + kIvSize);
        status = BCryptDecrypt(
            aesKey.handle,
            const_cast<PUCHAR>(&input[0]),
            static_cast<ULONG>(input.size()),
            NULL,
            &ivCopy[0],
            static_cast<ULONG>(ivCopy.size()),
            &output[0],
            static_cast<ULONG>(output.size()),
            &outputSize,
            BCRYPT_BLOCK_PADDING);
        if (status < 0)
        {
            error = StatusError(L"BCryptDecrypt", status);
            return false;
        }

        output.resize(outputSize);
        return true;
    }
}

bool UnprotectBytes(
    const std::vector<unsigned char>& protectedBytes,
    std::vector<unsigned char>& plain,
    std::wstring& error)
{
    plain.clear();
    if (protectedBytes.size() < sizeof(ProtectedHeader))
    {
        error = L"Arquivo Nexora pequeno demais.";
        return false;
    }

    ProtectedHeader header = {};
    memcpy(&header, &protectedBytes[0], sizeof(header));
    if (memcmp(header.magic, kMagic, sizeof(kMagic)) != 0 ||
        header.version != kVersion ||
        header.headerSize != sizeof(ProtectedHeader))
    {
        error = L"Formato Nexora invalido.";
        return false;
    }

    std::vector<unsigned char> encrypted(
        protectedBytes.begin() + sizeof(ProtectedHeader),
        protectedBytes.end());
    if (encrypted.empty())
    {
        error = L"Arquivo Nexora sem conteudo.";
        return false;
    }

    std::vector<unsigned char> authKey;
    if (!DeriveKey("auth", authKey, error))
        return false;

    std::vector<unsigned char> expectedTag;
    if (!HmacSha256(authKey, HeaderBytesWithZeroTag(header), encrypted, expectedTag, error))
        return false;

    if (!FixedTimeEquals(header.tag, &expectedTag[0], sizeof(header.tag)))
    {
        error = L"Assinatura Nexora invalida.";
        return false;
    }

    std::vector<unsigned char> cryptKey;
    if (!DeriveKey("crypt", cryptKey, error))
        return false;

    if (!AesDecrypt(encrypted, cryptKey, header.iv, plain, error))
        return false;

    if (plain.size() != static_cast<size_t>(header.plainSize))
    {
        error = L"Tamanho Nexora descriptografado invalido.";
        plain.clear();
        return false;
    }

    return true;
}

bool IsProtectedFile(const wchar_t* file)
{
    std::ifstream input(file, std::ios::binary);
    if (!input)
        return false;

    ProtectedHeader header = {};
    input.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (input.gcount() != sizeof(header))
        return false;

    return memcmp(header.magic, kMagic, sizeof(kMagic)) == 0 &&
        header.version == kVersion &&
        header.headerSize == sizeof(ProtectedHeader);
}

bool UnprotectFile(const wchar_t* source, const wchar_t* destination, std::wstring& error)
{
    std::vector<unsigned char> protectedBytes;
    if (!ReadFileBytes(source, protectedBytes))
    {
        error = L"Nao consegui ler arquivo protegido Nexora.";
        return false;
    }

    std::vector<unsigned char> plain;
    if (!UnprotectBytes(protectedBytes, plain, error))
        return false;

    if (!WriteFileBytes(destination, plain))
    {
        error = L"Nao consegui gravar temporario Nexora.";
        return false;
    }
    return true;
}

}
