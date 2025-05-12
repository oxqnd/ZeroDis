#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct Instruction {
    uint64_t address;                 // ��ɾ� ���� �ּ�
    std::vector<uint8_t> bytes;       // ���� ����Ʈ
    std::string mnemonic;             // ��ɾ� (ex: mov)
    std::string operands;             // ���۷��� (ex: rax, rbx)
    std::string label;                // �� ��ɾ� ��ġ�� ���� �� (��: L1)
    std::string comment;              // �ּ� (����)

    std::string toString(bool show_bytes = true) const;
};
