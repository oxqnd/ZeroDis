#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct Instruction {
    uint64_t address;                 // 명령어 시작 주소
    std::vector<uint8_t> bytes;       // 원시 바이트
    std::string mnemonic;             // 명령어 (ex: mov)
    std::string operands;             // 오퍼랜드 (ex: rax, rbx)
    std::string label;                // 이 명령어 위치에 붙은 라벨 (예: L1)
    std::string comment;              // 주석 (선택)

    std::string toString(bool show_bytes = true) const;
};
