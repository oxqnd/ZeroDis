#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "instruction.h"

struct DisasmOptions {
    bool show_bytes = true;
    bool use_labels = true;
    bool output_json = false;
    bool trace_calls = true;
};

class Disassembler {
public:
    Disassembler(const std::vector<uint8_t>& code, uint64_t base_addr);

    void analyze();  // 라벨 수집 + 함수 시작점 추적
    void decode();   // 실제 디스어셈블 수행
    void setOptions(const DisasmOptions& opt);

    const std::vector<Instruction>& getInstructions() const;

private:
    std::vector<uint8_t> code;
    uint64_t base_addr;
    std::vector<Instruction> instructions;
    std::unordered_map<uint64_t, std::string> label_map;
    DisasmOptions options;

    void firstPass_collectLabels();
    void secondPass_decode();
    void assignLabels();
    void addInstruction(const Instruction& inst);
};
