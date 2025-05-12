#include "pe_loader.h"
#include <fstream>
#include <iostream>
#include <cstring>

#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;    // "MZ"
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

bool load_text_section(const std::string& filename, std::vector<uint8_t>& out, uint64_t& base_address) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;

    IMAGE_DOS_HEADER dos;
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != 0x5A4D) return false;

    file.seekg(dos.e_lfanew);
    IMAGE_NT_HEADERS64 nt;
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (nt.Signature != 0x00004550) return false; // PE\0\0

    base_address = nt.OptionalHeader.ImageBase;
    int num_sections = nt.FileHeader.NumberOfSections;

    for (int i = 0; i < num_sections; ++i) {
        IMAGE_SECTION_HEADER sec;
        file.read(reinterpret_cast<char*>(&sec), sizeof(sec));

        if (std::strncmp(sec.Name, ".text", 5) == 0) {
            uint32_t size = sec.SizeOfRawData;
            if (size == 0) size = sec.VirtualSize;  // fallback

            if (size == 0 || sec.PointerToRawData == 0) {
                std::cerr << "[경고] .text 섹션의 크기 또는 위치가 0입니다.\n";
                return false;
            }

            out.resize(size);
            file.seekg(sec.PointerToRawData);
            file.read(reinterpret_cast<char*>(out.data()), size);
            base_address += sec.VirtualAddress;
            return true;
        }
    }

    return false;
}
