// Hooks BankPanelDraw. Each frame:
// - Finds search_input widget, exposes it for WndProcHook
// - Tracks click-based "input enabled" state
// - Syncs widget +0x551 focus byte to g_inputEnabled
// - Detects DropGoldModal-open for WndProcHook
// - Reads search text, logs match count for the visible tab
// - Determines visible tab index (BankTabs > ImageN +0x90 == 1)
// - Computes current containerId: Personal=1, Shared=sharedBase+(tabIdx-1)
//   where sharedBase = *(uint32_t*)(*(pInventory+0x68))
// - Walks unit hash for items with page=7 AND containerId==current,
//   reads each item's grid (cx,cy) from *(pItem+0x38)+0x10/+0x14
// - Builds 16x13 match grid, darkens cells that don't contain a matching
//   item (translucent black overlay). Empty cells are also darkened.
#include <Windows.h>
#include <MinHook.h>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <atomic>
#include "Pattern.h"

namespace {
    constexpr uint32_t RVA_BankPanelDraw = 0x18EB90;
    constexpr uint32_t RVA_WidgetFindChild = 0x576070;
    constexpr uint32_t RVA_StringTableLookup = 0x413860;
    constexpr uint32_t RVA_ItemsTablePtr = 0x1CA0390;
    constexpr uint32_t RVA_ItemsTableCount = 0x1CA0398;
    constexpr uint32_t RVA_StringTablePtr = 0x1856688;
    constexpr uint32_t RVA_UnitHashItems = 0x1D442E0 + 4 * 0x400;
    constexpr uint32_t RVA_PlayerUnitHash = 0x1D442E0;
    constexpr uint32_t RVA_PanelManager = 0x1D7C4E8;
    constexpr uint32_t RVA_DrawFilledRect = 0x439280;

    constexpr size_t OFF_UnitClassId = 0x04;
    constexpr size_t OFF_UnitItemData = 0x10;
    constexpr size_t OFF_UnitStaticPath = 0x38;
    constexpr size_t OFF_UnitInventory = 0x90;
    constexpr size_t OFF_UnitNext = 0x150;

    constexpr size_t OFF_ItemDataContainerId = 0x0C;
    constexpr size_t OFF_ItemDataPage = 0xB8;
    constexpr size_t ROW_STRIDE = 0x1B4;
    constexpr size_t OFF_RowNameId = 0xFC;

    constexpr size_t OFF_StaticPathX = 0x10;
    constexpr size_t OFF_StaticPathY = 0x14;

    constexpr size_t OFF_InvSharedTabsPtr = 0x68;

    constexpr size_t OFF_WidgetRectX = 0x70;
    constexpr size_t OFF_WidgetRectY = 0x74;
    constexpr size_t OFF_WidgetRectW = 0x78;
    constexpr size_t OFF_WidgetRectH = 0x7C;

    constexpr size_t OFF_WidgetString = 0x520;
    constexpr size_t OFF_WidgetStringSize = 0x528;
    constexpr size_t OFF_WidgetStringCap = 0x530;
    constexpr size_t OFF_WidgetStringInline = 0x538;

    constexpr size_t OFF_WidgetFocused = 0x551;
    constexpr size_t OFF_TabImageActive = 0x90;

    constexpr size_t OFF_NodeNamePtr = 0x08;
    constexpr size_t OFF_NodeChildren = 0x58;
    constexpr size_t OFF_NodeChildCnt = 0x60;

    constexpr size_t OFF_RowInvWidth = 0x116;
    constexpr size_t OFF_RowInvHeight = 0x117;

    constexpr float VIRTUAL_HEIGHT = 2160.0f;

    // Stash grid origin in screen pixels at 1920x1080. Cell (0,0) top-left.
    constexpr int GRID_ORIGIN_X = 46;
    constexpr int GRID_ORIGIN_Y = 122;
    constexpr int CELL_PX = 49;
    constexpr int STASH_W = 16;
    constexpr int STASH_H = 13;

    constexpr uint32_t PAGE_STASH = 7;
    constexpr uint32_t PERSONAL_CONTAINER_ID = 1;

    using BankPanelDraw_t = void(__fastcall*)(void* pBankPanel);
    using WidgetFindChild_t = void* (__fastcall*)(void* pParent, const char* name);
    using StringLookup_t = const char* (__fastcall*)(uint16_t key, void* stringTable);
    using DrawFilledRect_t = void(__fastcall*)(int x1, int y1, int x2, int y2, const float color[4]);

    BankPanelDraw_t   oBankPanelDraw = nullptr;
    WidgetFindChild_t pWidgetFindChild = nullptr;
    StringLookup_t    pStringLookup = nullptr;
    DrawFilledRect_t  pDrawFilledRect = nullptr;

    std::atomic<void*> g_searchWidget{ nullptr };
    std::atomic<DWORD> g_lastSeenTick{ 0 };
    std::atomic<bool>  g_inputEnabled{ false };
    std::atomic<bool>  g_dropGoldModalOpen{ false };

    bool g_prevMouseDown = false;
    bool g_clickInitialized = false;

    size_t ReadSearchText(void* pWidget, char* out, size_t outCap) {
        if (!pWidget || outCap == 0) return 0;
        auto base = reinterpret_cast<uint8_t*>(pWidget);
        size_t size = *reinterpret_cast<size_t*>(base + OFF_WidgetStringSize);
        if (size > 255) return 0;
        size_t cap = *reinterpret_cast<size_t*>(base + OFF_WidgetStringCap);
        bool isInline = (cap & 0x8000000000000000ULL) != 0;
        const char* src = isInline
            ? reinterpret_cast<const char*>(base + OFF_WidgetStringInline)
            : *reinterpret_cast<const char**>(base + OFF_WidgetString);
        if (!src) return 0;
        size_t n = (size < outCap - 1) ? size : (outCap - 1);
        memcpy(out, src, n);
        out[n] = '\0';
        return n;
    }

    // Reads item inventory width/height (in cells) from the items table.
    // Returns false on bad classId or null table.
    bool GetItemDimensions(uint32_t classId, uint8_t& outW, uint8_t& outH) {
        auto itemsBase = *reinterpret_cast<uint8_t**>(Pattern::Address(RVA_ItemsTablePtr));
        auto maxId = *reinterpret_cast<uint32_t*>(Pattern::Address(RVA_ItemsTableCount));
        if (!itemsBase || classId >= maxId) return false;
        uint8_t* row = itemsBase + classId * ROW_STRIDE;
        outW = *(row + OFF_RowInvWidth);
        outH = *(row + OFF_RowInvHeight);
        return true;
    }

    void StripColorCodes(const char* src, char* out, size_t outCap) {
        if (outCap == 0) return;
        size_t w = 0;
        for (size_t i = 0; src[i] != '\0' && w + 1 < outCap; ) {
            uint8_t b = static_cast<uint8_t>(src[i]);
            if (b == 0xFF && src[i + 1] == 'c' && src[i + 2] != '\0') { i += 3; continue; }
            out[w++] = src[i++];
        }
        out[w] = '\0';
    }

    bool ContainsCI(const char* haystack, const char* needle) {
        if (!needle || !*needle) return true;
        for (size_t i = 0; haystack[i] != '\0'; i++) {
            size_t j = 0;
            while (needle[j] != '\0' && haystack[i + j] != '\0' &&
                std::tolower(static_cast<uint8_t>(haystack[i + j])) ==
                std::tolower(static_cast<uint8_t>(needle[j]))) {
                j++;
            }
            if (needle[j] == '\0') return true;
        }
        return false;
    }

    const char* ResolveItemName(uint32_t classId) {
        auto itemsBase = *reinterpret_cast<uint8_t**>(Pattern::Address(RVA_ItemsTablePtr));
        auto maxId = *reinterpret_cast<uint32_t*>(Pattern::Address(RVA_ItemsTableCount));
        if (!itemsBase || classId >= maxId) return nullptr;
        uint16_t nameId = *reinterpret_cast<uint16_t*>(itemsBase + classId * ROW_STRIDE + OFF_RowNameId);
        void* stringTable = *reinterpret_cast<void**>(Pattern::Address(RVA_StringTablePtr));
        if (!stringTable) return nullptr;
        const char* result = pStringLookup(nameId, stringTable);
        if (!result || reinterpret_cast<const void*>(result) == stringTable) return nullptr;
        return result;
    }

    bool ItemMatches(uint8_t* pItem, const char* needle) {
        if (!pItem) return false;
        uint32_t classId = *reinterpret_cast<uint32_t*>(pItem + OFF_UnitClassId);
        const char* raw = ResolveItemName(classId);
        if (!raw) return false;
        char clean[128];
        StripColorCodes(raw, clean, sizeof(clean));
        return ContainsCI(clean, needle);
    }

    bool PointInWidget(void* pWidget, int virtualX, int virtualY) {
        auto base = reinterpret_cast<uint8_t*>(pWidget);
        int x = *reinterpret_cast<int32_t*>(base + OFF_WidgetRectX);
        int y = *reinterpret_cast<int32_t*>(base + OFF_WidgetRectY);
        int w = *reinterpret_cast<int32_t*>(base + OFF_WidgetRectW);
        int h = *reinterpret_cast<int32_t*>(base + OFF_WidgetRectH);
        return virtualX >= x && virtualX < (x + w)
            && virtualY >= y && virtualY < (y + h);
    }

    bool HasNamedDescendant(uint8_t* node, const char* name, int depth) {
        if (!node || depth > 8) return false;
        const char* np = *reinterpret_cast<const char**>(node + OFF_NodeNamePtr);
        if (np) {
            __try {
                if (strcmp(np, name) == 0) return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        uint8_t** data = *reinterpret_cast<uint8_t***>(node + OFF_NodeChildren);
        uint64_t count = *reinterpret_cast<uint64_t*>(node + OFF_NodeChildCnt);
        if (!data || count == 0 || count > 256) return false;
        for (uint64_t i = 0; i < count; i++) {
            if (HasNamedDescendant(data[i], name, depth + 1)) return true;
        }
        return false;
    }

    // Find a named descendant pointer (returns the node).
    uint8_t* FindNamedDescendant(uint8_t* node, const char* name, int depth) {
        if (!node || depth > 8) return nullptr;
        const char* np = *reinterpret_cast<const char**>(node + OFF_NodeNamePtr);
        if (np) {
            __try {
                if (strcmp(np, name) == 0) return node;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        uint8_t** data = *reinterpret_cast<uint8_t***>(node + OFF_NodeChildren);
        uint64_t count = *reinterpret_cast<uint64_t*>(node + OFF_NodeChildCnt);
        if (!data || count == 0 || count > 256) return nullptr;
        for (uint64_t i = 0; i < count; i++) {
            uint8_t* r = FindNamedDescendant(data[i], name, depth + 1);
            if (r) return r;
        }
        return nullptr;
    }

    void UpdateInputEnabledFromClick(void* pSearch) {
        bool mouseDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
        if (!g_clickInitialized) {
            g_prevMouseDown = mouseDown;
            g_clickInitialized = true;
            return;
        }
        bool risingEdge = mouseDown && !g_prevMouseDown;
        g_prevMouseDown = mouseDown;
        if (!risingEdge) return;
        HWND hWnd = GetForegroundWindow();
        if (!hWnd) return;
        POINT cursor;
        if (!GetCursorPos(&cursor)) return;
        if (!ScreenToClient(hWnd, &cursor)) return;
        RECT client;
        if (!GetClientRect(hWnd, &client)) return;
        int clientH = client.bottom - client.top;
        if (clientH <= 0) return;
        float scale = VIRTUAL_HEIGHT / static_cast<float>(clientH);
        int virtualX = static_cast<int>(cursor.x * scale);
        int virtualY = static_cast<int>(cursor.y * scale);
        bool clickedInside = PointInWidget(pSearch, virtualX, virtualY);
        g_inputEnabled.store(clickedInside, std::memory_order_relaxed);
    }

    void SyncFocusByte(void* pSearch) {
        auto base = reinterpret_cast<uint8_t*>(pSearch);
        uint8_t target = g_inputEnabled.load(std::memory_order_relaxed) ? 1 : 0;
        *(base + OFF_WidgetFocused) = target;
    }

    uint8_t* FindPlayerUnit() {
        auto buckets = reinterpret_cast<uint8_t**>(Pattern::Address(RVA_PlayerUnitHash));
        for (int i = 0; i < 128; i++) {
            auto unit = buckets[i];
            while (unit) {
                if (*reinterpret_cast<uint32_t*>(unit) == 0) return unit;
                unit = *reinterpret_cast<uint8_t**>(unit + OFF_UnitNext);
            }
        }
        return nullptr;
    }

    // Returns the active tab index (0=Personal, 1..7=Shared) by scanning
    // BankTabs children for the Image whose +0x90 byte is 1. Returns -1
    // if not found.
    int GetActiveTabIndex(void* pBankPanel) {
        void* pTabs = pWidgetFindChild(pBankPanel, "BankTabs");
        if (!pTabs) return -1;
        auto base = reinterpret_cast<uint8_t*>(pTabs);
        uint8_t** data = *reinterpret_cast<uint8_t***>(base + OFF_NodeChildren);
        uint64_t count = *reinterpret_cast<uint64_t*>(base + OFF_NodeChildCnt);
        if (!data || count == 0 || count > 256) return -1;
        // Children alternate ImageN, TextN. Walk all children, find Image
        // with +0x90 = 1.
        for (uint64_t i = 0; i < count; i++) {
            uint8_t* child = data[i];
            if (!child) continue;
            const char* name = *reinterpret_cast<const char**>(child + OFF_NodeNamePtr);
            if (!name) continue;
            if (name[0] == 'I' && name[1] == 'm' && name[2] == 'a' && name[3] == 'g' && name[4] == 'e') {
                uint8_t active = *(child + OFF_TabImageActive);
                if (active == 1) {
                    int idx = atoi(name + 5);
                    return idx;
                }
            }
        }
        return -1;
    }

    // Returns the shared-tab base container ID. The 7 shared tabs use
    // sequential IDs starting from this base. Personal stash uses ID 1.
    bool GetSharedTabBaseId(uint32_t& outBase) {
        uint8_t* player = FindPlayerUnit();
        if (!player) return false;
        uint8_t* pInv = *reinterpret_cast<uint8_t**>(player + OFF_UnitInventory);
        if (!pInv) return false;
        uint8_t* tab1 = *reinterpret_cast<uint8_t**>(pInv + OFF_InvSharedTabsPtr);
        if (!tab1) return false;
        outBase = *reinterpret_cast<uint32_t*>(tab1);
        return true;
    }

    // Compute the containerId of the current visible tab, or 0 if unknown.
    uint32_t GetVisibleContainerId(void* pBankPanel) {
        int tabIdx = GetActiveTabIndex(pBankPanel);
        if (tabIdx < 0) return 0;
        if (tabIdx == 0) return PERSONAL_CONTAINER_ID;
        uint32_t base = 0;
        if (!GetSharedTabBaseId(base)) return 0;
        return base + static_cast<uint32_t>(tabIdx - 1);
    }

    // Walk every stash item visible in the current tab. For each matching
    // item, mark its (cx, cy) cell as "matching". Then darken every cell
    // that is NOT marked. Empty cells get darkened too.
    void DarkenNonMatchingCells(const char* needle, void* pBankPanel) {
        if (!needle || !*needle || !pDrawFilledRect) return;
        uint32_t visibleCid = GetVisibleContainerId(pBankPanel);
        if (visibleCid == 0) return;

        bool match[STASH_W * STASH_H] = {};

        auto buckets = reinterpret_cast<uint8_t**>(Pattern::Address(RVA_UnitHashItems));
        for (int i = 0; i < 128; i++) {
            auto unit = buckets[i];
            while (unit) {
                auto pItemData = *reinterpret_cast<uint8_t**>(unit + OFF_UnitItemData);
                if (pItemData && pItemData[OFF_ItemDataPage] == PAGE_STASH) {
                    uint32_t cid = *reinterpret_cast<uint32_t*>(pItemData + OFF_ItemDataContainerId);
                    if (cid == visibleCid && ItemMatches(unit, needle)) {
                        auto pStaticPath = *reinterpret_cast<uint8_t**>(unit + OFF_UnitStaticPath);
                        if (pStaticPath) {
                            uint32_t cx = *reinterpret_cast<uint32_t*>(pStaticPath + OFF_StaticPathX);
                            uint32_t cy = *reinterpret_cast<uint32_t*>(pStaticPath + OFF_StaticPathY);
                            uint32_t classId = *reinterpret_cast<uint32_t*>(unit + OFF_UnitClassId);
                            uint8_t iw = 1, ih = 1;
                            GetItemDimensions(classId, iw, ih);
                            if (iw == 0) iw = 1;
                            if (ih == 0) ih = 1;
                            for (uint32_t dy = 0; dy < ih; dy++) {
                                for (uint32_t dx = 0; dx < iw; dx++) {
                                    uint32_t mx = cx + dx;
                                    uint32_t my = cy + dy;
                                    if (mx < STASH_W && my < STASH_H) {
                                        match[my * STASH_W + mx] = true;
                                    }
                                }
                            }
                        }
                    }
                }
                unit = *reinterpret_cast<uint8_t**>(unit + OFF_UnitNext);
            }
        }

        static const float dim[4] = { 0.0f, 0.0f, 0.0f, 0.6f };
        for (int cy = 0; cy < STASH_H; cy++) {
            for (int cx = 0; cx < STASH_W; cx++) {
                if (match[cy * STASH_W + cx]) continue;
                int x1 = GRID_ORIGIN_X + cx * CELL_PX;
                int y1 = GRID_ORIGIN_Y + cy * CELL_PX;
                pDrawFilledRect(x1, y1, x1 + CELL_PX, y1 + CELL_PX, dim);
            }
        }
    }

    // Count matches in the current visible tab only.
    int CountVisibleTabMatches(const char* needle, void* pBankPanel) {
        uint32_t visibleCid = GetVisibleContainerId(pBankPanel);
        if (visibleCid == 0) return 0;
        auto buckets = reinterpret_cast<uint8_t**>(Pattern::Address(RVA_UnitHashItems));
        int matches = 0;
        for (int i = 0; i < 128; i++) {
            auto unit = buckets[i];
            while (unit) {
                auto pItemData = *reinterpret_cast<uint8_t**>(unit + OFF_UnitItemData);
                if (pItemData && pItemData[OFF_ItemDataPage] == PAGE_STASH) {
                    uint32_t cid = *reinterpret_cast<uint32_t*>(pItemData + OFF_ItemDataContainerId);
                    if (cid == visibleCid && ItemMatches(unit, needle)) {
                        matches++;
                    }
                }
                unit = *reinterpret_cast<uint8_t**>(unit + OFF_UnitNext);
            }
        }
        return matches;
    }

    void __fastcall HookedBankPanelDraw(void* pBankPanel) {
        oBankPanelDraw(pBankPanel);

        auto pPanelMgr = *reinterpret_cast<uint8_t**>(Pattern::Address(RVA_PanelManager));
        bool modalOpen = pPanelMgr && HasNamedDescendant(pPanelMgr, "DropGoldModal", 0);
        g_dropGoldModalOpen.store(modalOpen, std::memory_order_relaxed);

        void* pSearch = pWidgetFindChild(pBankPanel, "search_input");
        g_searchWidget.store(pSearch, std::memory_order_relaxed);
        if (!pSearch) {
            g_inputEnabled.store(false, std::memory_order_relaxed);
            g_clickInitialized = false;
            return;
        }

        g_lastSeenTick.store(GetTickCount(), std::memory_order_relaxed);

        UpdateInputEnabledFromClick(pSearch);
        SyncFocusByte(pSearch);

        char text[256] = {};
        ReadSearchText(pSearch, text, sizeof(text));

        DarkenNonMatchingCells(text, pBankPanel);
    }
}

bool IsSearchWidgetActive() {
    if (!g_inputEnabled.load(std::memory_order_relaxed)) return false;
    if (!g_searchWidget.load(std::memory_order_relaxed)) return false;
    DWORD last = g_lastSeenTick.load(std::memory_order_relaxed);
    DWORD now = GetTickCount();
    return (now - last) < 100;
}

void* GetSearchWidget() {
    if (!IsSearchWidgetActive()) return nullptr;
    return g_searchWidget.load(std::memory_order_relaxed);
}

void* GetSearchWidgetIfExists() {
    if (!g_searchWidget.load(std::memory_order_relaxed)) return nullptr;
    DWORD last = g_lastSeenTick.load(std::memory_order_relaxed);
    DWORD now = GetTickCount();
    if ((now - last) >= 100) return nullptr;
    return g_searchWidget.load(std::memory_order_relaxed);
}

bool IsDropGoldModalOpen() {
    return g_dropGoldModalOpen.load(std::memory_order_relaxed);
}

bool InstallBankPanelHook() {
    pWidgetFindChild = reinterpret_cast<WidgetFindChild_t>(Pattern::Address(RVA_WidgetFindChild));
    pStringLookup = reinterpret_cast<StringLookup_t>(Pattern::Address(RVA_StringTableLookup));
    pDrawFilledRect = reinterpret_cast<DrawFilledRect_t>(Pattern::Address(RVA_DrawFilledRect));
    LPVOID target = reinterpret_cast<LPVOID>(Pattern::Address(RVA_BankPanelDraw));
    if (MH_CreateHook(target,
        reinterpret_cast<LPVOID>(&HookedBankPanelDraw),
        reinterpret_cast<LPVOID*>(&oBankPanelDraw)) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        return false;
    }
    return true;
}

void UninstallBankPanelHook() {
    LPVOID target = reinterpret_cast<LPVOID>(Pattern::Address(RVA_BankPanelDraw));
    MH_DisableHook(target);
    MH_RemoveHook(target);
}