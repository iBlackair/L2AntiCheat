#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace NexoraDatCrypt
{
    bool IsProtectedFile(const wchar_t* file);
    bool UnprotectFile(const wchar_t* source, const wchar_t* destination, std::wstring& error);
    bool UnprotectBytes(
        const std::vector<unsigned char>& protectedBytes,
        std::vector<unsigned char>& plain,
        std::wstring& error);
}
