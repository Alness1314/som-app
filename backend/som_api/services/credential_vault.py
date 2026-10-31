"""Per-user Windows DPAPI encryption for secrets stored in SQLite."""
import ctypes
import os
from ctypes import wintypes


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(wintypes.BYTE))]


_ENTROPY = b"SecurityOperationsManager/device-credentials/v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _windows_apis():
    if os.name != "nt":
        raise RuntimeError("El almacén cifrado de credenciales requiere Windows y DPAPI.")
    crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob), wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_DataBlob), wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    return crypt32, kernel32


def _make_blob(raw: bytes):
    buffer = (wintypes.BYTE * len(raw)).from_buffer_copy(raw)
    return _DataBlob(len(raw), ctypes.cast(buffer, ctypes.POINTER(wintypes.BYTE))), buffer


def _entropy_blob():
    return _make_blob(_ENTROPY)


def protect_secret(value: str) -> bytes:
    """Encrypt UTF-8 data for the current Windows user (not machine-wide)."""
    crypt32, kernel32 = _windows_apis()
    data, data_buffer = _make_blob(value.encode("utf-8"))
    entropy, entropy_buffer = _entropy_blob()
    protected = _DataBlob()
    if not crypt32.CryptProtectData(ctypes.byref(data), "SOM device credential", ctypes.byref(entropy), None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(protected)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(protected.pbData, protected.cbData)
    finally:
        kernel32.LocalFree(protected.pbData)
        _ = data_buffer, entropy_buffer


def unprotect_secret(value: bytes) -> str:
    """Decrypt data previously protected by this SOM installation for this user."""
    crypt32, kernel32 = _windows_apis()
    data, data_buffer = _make_blob(value)
    entropy, entropy_buffer = _entropy_blob()
    unprotected = _DataBlob()
    if not crypt32.CryptUnprotectData(ctypes.byref(data), None, ctypes.byref(entropy), None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(unprotected)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(unprotected.pbData, unprotected.cbData).decode("utf-8")
    finally:
        kernel32.LocalFree(unprotected.pbData)
        _ = data_buffer, entropy_buffer
