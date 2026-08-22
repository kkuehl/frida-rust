/*
 * Minimal MSVC C++ runtime compat for prebuilt frida-gumjs-devkit on Windows.
 *
 * The official Frida devkit is built with a newer MSVC toolchain that
 * introduces vectorized algorithm helpers (__std_max_element_*,
 * __std_min_element_*, __std_rotate, etc.) not present in older
 * msvcprt/libcmt (e.g. VS 2022 v17.14 / link.exe 14.44.35207).
 *
 * Linking MimicAgentX.dll against frida-gumjs.lib currently fails with
 * 9 unresolved __std_* externals. This file provides simple fallback
 * implementations so the link succeeds on these toolchains.
 */

#include <stdlib.h>
#include <string.h>

/* max_element helpers ---------------------------------------------------- */

const void* __stdcall __std_max_element_4i(
    const void* const _First,
    const void* const _Last) {
    const int* first = (const int*)_First;
    const int* last  = (const int*)_Last;
    const int* max   = first;
    for (; first != last; ++first) {
        if (*first > *max) max = first;
    }
    return max;
}

const void* __stdcall __std_max_element_4u(
    const void* const _First,
    const void* const _Last) {
    const unsigned int* first = (const unsigned int*)_First;
    const unsigned int* last  = (const unsigned int*)_Last;
    const unsigned int* max   = first;
    for (; first != last; ++first) {
        if (*first > *max) max = first;
    }
    return max;
}

const void* __stdcall __std_max_element_8u(
    const void* const _First,
    const void* const _Last) {
    const unsigned long long* first = (const unsigned long long*)_First;
    const unsigned long long* last  = (const unsigned long long*)_Last;
    const unsigned long long* max   = first;
    for (; first != last; ++first) {
        if (*first > *max) max = first;
    }
    return max;
}

const void* __stdcall __std_max_element_d_(
    const void* const _First,
    const void* const _Last) {
    const double* first = (const double*)_First;
    const double* last  = (const double*)_Last;
    const double* max   = first;
    for (; first != last; ++first) {
        if (*first > *max) max = first;
    }
    return max;
}

/* min_element helpers ---------------------------------------------------- */

const void* __stdcall __std_min_element_4i(
    const void* const _First,
    const void* const _Last) {
    const int* first = (const int*)_First;
    const int* last  = (const int*)_Last;
    const int* min   = first;
    for (; first != last; ++first) {
        if (*first < *min) min = first;
    }
    return min;
}

const void* __stdcall __std_min_element_4u(
    const void* const _First,
    const void* const _Last) {
    const unsigned int* first = (const unsigned int*)_First;
    const unsigned int* last  = (const unsigned int*)_Last;
    const unsigned int* min   = first;
    for (; first != last; ++first) {
        if (*first < *min) min = first;
    }
    return min;
}

const void* __stdcall __std_min_element_8u(
    const void* const _First,
    const void* const _Last) {
    const unsigned long long* first = (const unsigned long long*)_First;
    const unsigned long long* last  = (const unsigned long long*)_Last;
    const unsigned long long* min   = first;
    for (; first != last; ++first) {
        if (*first < *min) min = first;
    }
    return min;
}

const void* __stdcall __std_min_element_d_(
    const void* const _First,
    const void* const _Last) {
    const double* first = (const double*)_First;
    const double* last  = (const double*)_Last;
    const double* min   = first;
    for (; first != last; ++first) {
        if (*first < *min) min = first;
    }
    return min;
}

/* rotate ----------------------------------------------------------------- */

void __stdcall __std_rotate(
    void* _First,
    void* const _Mid,
    void* _Last) {
    char* first = (char*)_First;
    char* mid   = (char*)_Mid;
    char* last  = (char*)_Last;

    size_t left  = (size_t)(mid - first);
    size_t right = (size_t)(last - mid);

    if (left == 0 || right == 0) return;

    size_t small = left < right ? left : right;
    void*  buf   = malloc(small);
    if (buf == NULL) return;  /* graceful fail-rotate */

    if (left <= right) {
        memcpy(buf, first, left);
        memmove(first, mid, right);
        memcpy(first + right, buf, left);
    } else {
        memcpy(buf, mid, right);
        memmove(first + right, first, left);
        memcpy(first, buf, right);
    }

    free(buf);
}
