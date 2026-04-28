#pragma once
#include <Windows.h>
#include <cstdint>

class Pattern
{
public:
    static uintptr_t BaseAddress() {
        static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        return base;
    }
    static uintptr_t Address(uint32_t rva) {
        return BaseAddress() + rva;
    }
};