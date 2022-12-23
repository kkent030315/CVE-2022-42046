# EvilWfshbr

[CVE-2022-42046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-42046) Proof of Concept of wfshbr64.sys local privilege escalation

wfshbr64.sys and wfshbr32.sys specially crafted payload allows arbitrary user to perform bitwise operation with arbitrary EPROCESS offset and flags value to purposely elevate the game process to CodeGen Full protection by manipulating `EPROCESS.Protection` and `EPROCESS.SignatureLevel` flags (security hole as a feature).

The driver is signed by Microsoft hardware compatibility publisher that is submitted via Microsoft Hardware Program.

This project was co-researched with [@DoranekoSystems](https://github.com/DoranekoSystems)

### **There is a rich Rust CLI version available [here](wfsexploit)**

- https://www.virustotal.com/gui/file/b8807e365be2813b7eccd2e4c49afb0d1e131086715638b7a6307cd7d7e9556c
- https://www.virustotal.com/gui/file/89698cad598a56f9e45efffd15d1841e494a2409cc12279150a03842cd6bb7f3

# License

MIT. See [LICENSE](LICENSE)

# Suggestion (For Developer)

1. Use [`ObRegisterCallbacks`](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) instead of forcefully elevating process protection by performing direct kernel object manipulation. There is a good example in [here](https://github.com/microsoft/Windows-driver-samples/tree/main/general/obcallback).

## 2. IRP

Do not reference IRP after completion. if you have driver verifier enabled you will get caught.

```cpp
IofCompleteRequest(Irp, IO_NO_INCREMENT); // IRP is freed here
return Irp->IoStatus.Status;
```

Instead you should use local variable.

```cpp
NTSTATUS status = STATUS_SUCCESS;
Irp->IoStatus.Status = status;
IofCompleteRequest(Irp, IO_NO_INCREMENT); // IRP is freed here
return status;
```

## 3. Context Process

It looks like you're checking null pointer against return value of `IoGetCurrentProcess`, but it never return null pointer by design so you do not have to check it.

```cpp
PEPROCESS CurrentProcess = IoGetCurrentProcess();
  if ( !CurrentProcess ) // no need to check for null pointer
    break;
```

# The Trick

A while after the report, the developer implemented sneaky "additional verification" to defeat our first PoC instead of stepping down from making security holes as a feature.

Checks added to:

- `IOCTL_WFSHBR_REMOVE_FLAG`
- `IOCTL_WFSHBR_ADD_FLAG`
- `IOCTL_WFSHBR_AND_FLAG`

```diff
case IOCTL_WFSHBR_ADD_FLAG: // 0xAA013884
      if ( !KwfsVerifyCaller(Buffer) ) // verify caller
        break;
-     if ( Buffer->ArbitraryEProcessOffset >= 0x1000 ) // offset limitation check
+     if ( !KwfsVerifyOffsetAndFlags(Buffer->ArbitraryEProcessOffset,
+                                    Buffer->DesiredFlags) ) // verify the offset and flags
        break;
      *(ULONG*)(IoGetCurrentProcess() + Buffer->ArbitraryEProcessOffset) |= Buffer->DesiredFlags;
```

## KwfsVerifyOffsetAndFlags

This routine is designed to be called every time the client requests modification of EPROCESS, and performs verification of `Offset` provided by `ArbitraryEProcessOffset` field in this PoC ― and also `Flags` provided by `DesiredFlags` field in this PoC.

The verification is quite simple as it counts `1` bits in every bits field of provided flags and if the count greater than eight it will fail.

Possible flags pattern map is just four:

- `22 00 00 00`
- `00 22 00 00`
- `00 00 22 00`
- `00 00 00 22`

That said, performing following operations 4 times can guarantee that the at least one of attempt should be successfull:

- Subtract the `ArbitraryEProcessOffset` field by index: `offset - index`,
- And adjust bits in `DesiredFlags` field by index: `flag << (index * 8)`.

The offset is decremented, so the bitfield adjustment would cause offset to adjust in the bitwise operators.

```cpp
*(ULONG*)(IoGetCurrentProcess() + offset) |= flags;
*(ULONG*)(IoGetCurrentProcess() + offset) &= ~flags;
```

We have added `WfsProtectProcessSupreme` and `WfsUnprotectProcessSupreme` functions which performs the attempt and defeated the new trick.

```cpp
enum KwfsState {
  KwfsStateOnceCall = 0,
  KwfsStateNeedsValueEquality = 1,
  KwfsStateValueHasBeenSet = 2,
};

bool KwfsVerifyOffsetAndFlags(_In_ ULONG offset, _In_ ULONG offset flags)
{
  if (KwfsState::KwfsState == KwfsState::KwfsStateOnceCall) {
    g_KwfsVerifyState = KwfsState::KwfsStateValueHasBeenSet;
    g_KwfsVerifyStateOffset = offset;
    g_KwfsVerifyStateFlags = flags;
    if (offset < 0x1000) { // offset limitation check moved here
      auto bitcount = 0;
      for (auto i = 0; i < 32; ++i) { // count `1` bits in flags
        if (flags & (1 << i)) {
          ++bitcount;
        }
      }
      if (bitcount <= 8) { // count must less than nine
        g_KwfsVerifyState = 1;
        return true;
      }
    }
  }
  else
  {
    if (g_KwfsVerifyState != KwfsState::KwfsStateValueHasBeenSet
     || offset != g_KwfsVerifyStateOffset
     || flags != g_KwfsVerifyStateFlags) {
      return false;
    }
  }
  return false;
}
```
