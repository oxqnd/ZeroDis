#include "disassembler.h"
#include <sstream>
#include <iomanip>
#include <queue>
#include <cstring>
#include <iostream> // 디버그용

static const char* reg64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

std::string format_memory_operand(uint8_t mod, uint8_t rm, uint8_t rex, const std::vector<uint8_t>& code, size_t& i) {
    std::ostringstream oss;
    uint8_t base = rm + ((rex & 0x1) ? 8 : 0);
    if (rm == 4) {
        if (i >= code.size()) return "[??]";
        uint8_t sib = code[i++];
        uint8_t scale = (sib >> 6) & 0x3;
        uint8_t index = (sib >> 3) & 0x7;
        uint8_t base_sib = sib & 0x7;

        uint8_t index_ext = (rex & 0x2) ? 8 : 0;
        uint8_t base_ext = (rex & 0x1) ? 8 : 0;

        std::string base_str = reg64[base_sib + base_ext];
        std::string index_str = reg64[index + index_ext];

        oss << "[" << base_str;
        if (index != 4) {
            oss << "+" << index_str << "*" << (1 << scale);
        }
        if (mod == 1 && i < code.size()) {
            int8_t disp8 = static_cast<int8_t>(code[i++]);
            oss << ((disp8 >= 0) ? "+0x" : "-0x") << std::hex << std::abs(disp8);
        }
        else if (mod == 2 && i + 4 <= code.size()) {
            int32_t disp32 = *reinterpret_cast<const int32_t*>(&code[i]);
            i += 4;
            oss << ((disp32 >= 0) ? "+0x" : "-0x") << std::hex << std::abs(disp32);
        }
        oss << "]";
    }
    else {
        oss << "[" << reg64[base];
        if (mod == 1 && i < code.size()) {
            int8_t disp8 = static_cast<int8_t>(code[i++]);
            oss << ((disp8 >= 0) ? "+0x" : "-0x") << std::hex << std::abs(disp8);
        }
        else if (mod == 2 && i + 4 <= code.size()) {
            int32_t disp32 = *reinterpret_cast<const int32_t*>(&code[i]);
            i += 4;
            oss << ((disp32 >= 0) ? "+0x" : "-0x") << std::hex << std::abs(disp32);
        }
        oss << "]";
    }
    return oss.str();
}

Disassembler::Disassembler(const std::vector<uint8_t>& code, uint64_t base_addr)
    : code(code), base_addr(base_addr) {
}

void Disassembler::setOptions(const DisasmOptions& opt) {
    options = opt;
}

void Disassembler::analyze() {
    firstPass_collectLabels();
}

void Disassembler::decode() {
    secondPass_decode();
    assignLabels();
}

const std::vector<Instruction>& Disassembler::getInstructions() const {
    return instructions;
}

void Disassembler::firstPass_collectLabels() {
    std::queue<uint64_t> queue;
    std::unordered_map<uint64_t, bool> visited;

    queue.push(base_addr);
    visited[base_addr] = true;

    while (!queue.empty()) {
        uint64_t addr = queue.front(); queue.pop();
        size_t i = addr - base_addr;
        while (i < code.size()) {
            uint8_t byte = code[i];
            if (byte == 0xE9 && i + 4 < code.size()) {
                int32_t offset = *reinterpret_cast<const int32_t*>(&code[i + 1]);
                uint64_t target = addr + 5 + offset;
                label_map[target] = "L" + std::to_string(label_map.size());
                if (!visited[target]) {
                    queue.push(target);
                    visited[target] = true;
                }
                break;
            }
            if (byte >= 0x70 && byte <= 0x7F && i + 1 < code.size()) {
                int8_t offset = static_cast<int8_t>(code[i + 1]);
                uint64_t target = addr + 2 + offset;
                label_map[target] = "L" + std::to_string(label_map.size());
                if (!visited[target]) {
                    queue.push(target);
                    visited[target] = true;
                }
                i += 2;
                continue;
            }
            if (byte == 0xC3) break;
            i++;
        }
    }
}

void Disassembler::secondPass_decode() {
    size_t i = 0;
    while (i < code.size()) {
        Instruction inst;
        inst.address = base_addr + i;
        size_t start = i;
        uint8_t rex = 0;
        if ((code[i] & 0xF0) == 0x40) {
            rex = code[i++];
            if (i >= code.size()) break;
        }
        if (i >= code.size()) break;
        uint8_t opcode = code[i++];
        uint8_t next = (i < code.size()) ? code[i] : 0;

        auto get_reg = [&](int r) { return reg64[r + ((rex & 0x1) ? 8 : 0)]; };

        bool matched = false;

        try {
            if (opcode == 0xC3) {
                inst.mnemonic = "ret";
                matched = true;
            }
            else if (opcode == 0xE8 && i + 4 <= code.size()) {
                int32_t offset = *reinterpret_cast<const int32_t*>(&code[i]);
                i += 4;
                uint64_t target = inst.address + (i - start) + offset;
                inst.mnemonic = "call";
                inst.operands = label_map.count(target) ? label_map[target] : "0x" + std::to_string(target);
                matched = true;
            }
            else if (opcode >= 0x50 && opcode <= 0x5F) {
                inst.mnemonic = (opcode < 0x58) ? "push" : "pop";
                inst.operands = reg64[(opcode & 0x7) + ((rex & 0x1) ? 8 : 0)];
                matched = true;
            }
            else if ((opcode == 0x01 || opcode == 0x29 || opcode == 0x39 || opcode == 0x3B || opcode == 0x8B || opcode == 0x89 || opcode == 0x85 || opcode == 0x21 || opcode == 0x09 || opcode == 0x31) && i < code.size()) {
                uint8_t modrm = code[i++];
                uint8_t mod = (modrm >> 6) & 0x3;
                uint8_t reg = (modrm >> 3) & 0x7;
                uint8_t rm = modrm & 0x7;
                const char* reg_str = get_reg(reg);
                std::ostringstream oss;

                switch (opcode) {
                case 0x01: inst.mnemonic = "add"; break;
                case 0x29: inst.mnemonic = "sub"; break;
                case 0x39: inst.mnemonic = "cmp"; break;
                case 0x3B: inst.mnemonic = "cmp"; break;
                case 0x89: inst.mnemonic = "mov"; break;
                case 0x8B: inst.mnemonic = "mov"; break;
                case 0x85: inst.mnemonic = "test"; break;
                case 0x21: inst.mnemonic = "and"; break;
                case 0x09: inst.mnemonic = "or"; break;
                case 0x31: inst.mnemonic = "xor"; break;
                }

                oss << reg_str << ", " << ((mod == 3) ? get_reg(rm) : format_memory_operand(mod, rm, rex, code, i));
                inst.operands = oss.str();
                matched = true;
            }
            else if (opcode == 0xF7 && i < code.size()) {
                uint8_t modrm = code[i++];
                uint8_t reg = (modrm >> 3) & 0x7;
                uint8_t rm = modrm & 0x7;
                static const char* ops[] = { "??", "not", "neg", "mul", "imul", "div", "idiv" };
                if (reg >= 1 && reg <= 6) {
                    inst.mnemonic = ops[reg];
                    inst.operands = (modrm >> 6 == 3) ? get_reg(rm) : format_memory_operand((modrm >> 6) & 0x3, rm, rex, code, i);
                    matched = true;
                }
            }
            else if (opcode == 0x8D && i < code.size()) {
                uint8_t modrm = code[i++];
                uint8_t reg = (modrm >> 3) & 0x7;
                uint8_t rm = modrm & 0x7;
                inst.mnemonic = "lea";
                std::ostringstream oss;
                oss << get_reg(reg) << ", " << format_memory_operand((modrm >> 6) & 0x3, rm, rex, code, i);
                inst.operands = oss.str();
                matched = true;
            }
            else if (opcode >= 0x70 && opcode <= 0x7F && i < code.size()) {
                int8_t offset = static_cast<int8_t>(code[i++]);
                static const char* jcc_table[16] = {
                    "jo","jno","jb","jae","je","jne","jbe","ja",
                    "js","jns","jp","jnp","jl","jge","jle","jg"
                };
                uint64_t target = inst.address + (i - start) + offset;
                inst.mnemonic = jcc_table[opcode - 0x70];
                inst.operands = label_map.count(target) ? label_map[target] : "0x" + std::to_string(target);
                matched = true;
            }
            else if (opcode == 0xE9 && i + 4 <= code.size()) {
                int32_t offset = *reinterpret_cast<const int32_t*>(&code[i]);
                i += 4;
                uint64_t target = inst.address + (i - start) + offset;
                inst.mnemonic = "jmp";
                inst.operands = label_map.count(target) ? label_map[target] : "0x" + std::to_string(target);
                matched = true;
            }
        }
        catch (...) {
            inst.mnemonic = "??";
        }

        if (!matched) inst.mnemonic = "??";

        inst.bytes.insert(inst.bytes.end(), code.begin() + start, code.begin() + i);
        //std::cerr << "[디버그] " << std::hex << inst.address << ": " << inst.mnemonic << "";
        addInstruction(inst);
    }
}

void Disassembler::assignLabels() {
    for (auto& inst : instructions) {
        if (label_map.count(inst.address)) {
            inst.label = label_map[inst.address];
        }
    }
}

void Disassembler::addInstruction(const Instruction& inst) {
    instructions.push_back(inst);
}
