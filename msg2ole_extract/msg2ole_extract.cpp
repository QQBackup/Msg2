/*
 * CLI OLE compound document extractor — logic ported from QQMgrMsg_src/QQMgrMsg/ComFileExtr.cpp
 * (recursive IStorage::EnumElements → folders / IStream → files).
 *
 * Build (cross-compile on Linux): see Makefile, or
 *   x86_64-w64-mingw32-g++ -std=c++17 -O2 -municode -Wall -Wextra msg2ole_extract.cpp \
 *       -static -lole32 -luuid -lshell32 -o msg2ole_extract.exe
 * (-static avoids missing libwinpthread-1.dll when running under Wine.)
 *
 * Run on Windows: msg2ole_extract.exe Msg2.0.db out_dir
 * Run under Wine (Linux): wine msg2ole_extract.exe /unix/style/paths work
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <string>
#include <vector>

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

static void LogErr(const wchar_t* msg)
{
    fwprintf(stderr, L"%ls\n", msg);
}

static bool CopyStreamToFile(IStream* stm, const wchar_t* destPath)
{
    LARGE_INTEGER zero{};
    if (stm->Seek(zero, STREAM_SEEK_SET, nullptr) != S_OK)
    {
        LogErr(L"Seek stream failed");
        return false;
    }

    HANDLE h = CreateFileW(destPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        fwprintf(stderr, L"CreateFileW failed: %ls\n", destPath);
        return false;
    }

    constexpr DWORD chunk = 1024 * 1024;
    std::vector<unsigned char> buf(chunk);
    ULONG rd = 0;
    for (;;)
    {
        rd = 0;
        HRESULT hr = stm->Read(buf.data(), static_cast<ULONG>(buf.size()), &rd);
        if (hr != S_OK && hr != S_FALSE)
        {
            LogErr(L"IStream::Read failed");
            CloseHandle(h);
            return false;
        }
        if (rd == 0)
            break;
        DWORD wr = 0;
        if (!WriteFile(h, buf.data(), rd, &wr, nullptr) || wr != rd)
        {
            LogErr(L"WriteFile failed");
            CloseHandle(h);
            return false;
        }
        if (hr == S_FALSE || rd < buf.size())
            break;
    }
    CloseHandle(h);
    return true;
}

static void ExtrDB(IStorage* Istg, const std::wstring& strSubPath)
{
    IEnumSTATSTG* ppenum = nullptr;
    HRESULT hr = Istg->EnumElements(0, nullptr, 0, &ppenum);
    if (hr != S_OK || !ppenum)
    {
        fwprintf(stderr, L"EnumElements failed hr=0x%08lx path=%ls\n", static_cast<unsigned long>(hr),
                 strSubPath.c_str());
        return;
    }

    STATSTG SStg{};
    ULONG celt = 1;

    while (ppenum->Next(1, &SStg, &celt) == S_OK && celt == 1)
    {
        wchar_t* rawName = SStg.pwcsName;
        if (!rawName)
        {
            fwprintf(stderr, L"(unnamed element) type=%lu — skipped\n", static_cast<unsigned long>(SStg.type));
            continue;
        }

        if (SStg.type == STGTY_STORAGE)
        {
            std::wstring foldName = rawName;
            CoTaskMemFree(rawName);
            rawName = nullptr;

            std::wstring tstrSubPath = strSubPath + L"\\" + foldName;

            if (!CreateDirectoryW(tstrSubPath.c_str(), nullptr))
            {
                DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS)
                    fwprintf(stderr, L"CreateDirectoryW failed (%lu): %ls\n", err, tstrSubPath.c_str());
            }
            else
                wprintf(L"mkdir %ls\n", tstrSubPath.c_str());

            IStorage* tIstg = nullptr;
            hr = Istg->OpenStorage(foldName.c_str(), nullptr,
                                   STGM_READ | STGM_SHARE_EXCLUSIVE,
                                   nullptr, 0, &tIstg);

            if (hr == S_OK && tIstg)
            {
                ExtrDB(tIstg, tstrSubPath);
                tIstg->Release();
            }
            else
                fwprintf(stderr, L"OpenStorage failed %ls hr=0x%08lx\n", foldName.c_str(),
                         static_cast<unsigned long>(hr));
        }
        else if (SStg.type == STGTY_STREAM)
        {
            std::wstring streamName = rawName;
            CoTaskMemFree(rawName);
            rawName = nullptr;

            IStream* pStream = nullptr;
            hr = Istg->OpenStream(streamName.c_str(), nullptr,
                                  STGM_READ | STGM_SHARE_EXCLUSIVE,
                                  0, &pStream);
            if (hr != S_OK || !pStream)
            {
                fwprintf(stderr, L"OpenStream failed %ls hr=0x%08lx\n", streamName.c_str(),
                         static_cast<unsigned long>(hr));
                continue;
            }

            std::wstring tstrExtrPath = strSubPath + L"\\" + streamName;
            if (CopyStreamToFile(pStream, tstrExtrPath.c_str()))
                wprintf(L"file %ls\n", tstrExtrPath.c_str());
            pStream->Release();
        }
        else
        {
            fwprintf(stderr, L"skip type=%lu name=%ls\n", static_cast<unsigned long>(SStg.type), rawName);
            CoTaskMemFree(rawName);
        }
    }

    ppenum->Release();
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        fwprintf(stderr, L"Usage: %ls <Msg2.0.db path> <output directory>\n", argv[0]);
        return 1;
    }

    const wchar_t* dbPath = argv[1];
    const wchar_t* outDir = argv[2];

    if (!CreateDirectoryW(outDir, nullptr))
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
        {
            fwprintf(stderr, L"CreateDirectoryW output root failed (%lu): %ls\n", err, outDir);
            return 1;
        }
    }

    HRESULT comHr = CoInitialize(nullptr);
    if (comHr != S_OK && comHr != S_FALSE)
    {
        fwprintf(stderr, L"CoInitialize failed hr=0x%08lx\n", static_cast<unsigned long>(comHr));
        return 1;
    }

    IStorage* root = nullptr;
    HRESULT hr = StgOpenStorage(dbPath, nullptr,
                                STGM_READ | STGM_SHARE_DENY_WRITE,
                                nullptr, 0, &root);
    if (hr != S_OK || !root)
    {
        fwprintf(stderr, L"StgOpenStorage failed hr=0x%08lx for %ls\n", static_cast<unsigned long>(hr), dbPath);
        CoUninitialize();
        return 1;
    }

    fwprintf(stderr, L"Extracting to %ls ...\n", outDir);
    ExtrDB(root, std::wstring(outDir));
    root->Release();
    CoUninitialize();
    fwprintf(stderr, L"Done.\n");
    return 0;
}
