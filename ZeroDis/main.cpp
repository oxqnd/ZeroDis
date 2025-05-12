#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <cstring>
#include <iomanip>

#include "pe_loader.h"
#include "disassembler.h"
#include "instruction.h"

void print_help() {
    std::cout <<
        "사용법: ZeroDis <실행파일.exe> [옵션]\n"
        "옵션:\n"
        "  --nobytes        바이트 출력 생략\n"
        "  --nolabel        라벨 출력 생략\n"
        "  --json           JSON 형식 출력\n"
        "  --csv            CSV 형식 출력\n"
        "  --out filename   출력 내용을 파일로 저장\n"
        "  --help           도움말 표시\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    std::string filename = argv[1];
    std::string output_file;
    DisasmOptions options;
    bool csv_output = false;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--nobytes") == 0) {
            options.show_bytes = false;
        }
        else if (strcmp(argv[i], "--nolabel") == 0) {
            options.use_labels = false;
        }
        else if (strcmp(argv[i], "--json") == 0) {
            options.output_json = true;
        }
        else if (strcmp(argv[i], "--csv") == 0) {
            csv_output = true;
        }
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else {
            std::cerr << "[경고] 알 수 없는 옵션: " << argv[i] << "\n";
        }
    }

    std::vector<uint8_t> code;
    uint64_t base_addr = 0;

    if (!load_text_section(filename, code, base_addr)) {
        std::cerr << "[❌] PE 파일을 로드하지 못했습니다: " << filename << "\n";
        return 1;
    }

    Disassembler dis(code, base_addr);
    dis.setOptions(options);
    dis.analyze();
    dis.decode();
    const auto& instructions = dis.getInstructions();

    std::ostringstream output;

    if (options.output_json) {
        output << "[\n";
        for (size_t i = 0; i < instructions.size(); ++i) {
            const auto& inst = instructions[i];
            output << "  {\n"
                << "    \"address\": \"" << std::hex << inst.address << "\",\n"
                << "    \"mnemonic\": \"" << inst.mnemonic << "\",\n"
                << "    \"operands\": \"" << inst.operands << "\"\n"
                << "  }";
            if (i + 1 != instructions.size()) output << ",";
            output << "\n";
        }
        output << "]\n";
    }
    else if (csv_output) {
        output << "Label,AddressHex,AddressDec,ByteCount,BytesRaw,Mnemonic,Operands\n";
        for (const auto& inst : instructions) {
            output << (inst.label.empty() ? "" : inst.label) << ",";
            output << "0x" << std::hex << inst.address << ",";
            output << std::dec << inst.address << ",";
            output << inst.bytes.size() << ",";
            for (auto b : inst.bytes)
                output << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            output << "," << inst.mnemonic << "," << inst.operands << "\n";
        }
    }
    else {
        for (const auto& inst : instructions) {
            output << inst.toString(options.show_bytes) << "\n";
        }
    }

    if (!output_file.empty()) {
        std::ofstream out(output_file);
        if (!out) {
            std::cerr << "[❌] 파일을 열 수 없습니다: " << output_file << "\n";
            return 1;
        }
        out << output.str();
        std::cout << "[💾] 결과가 파일로 저장되었습니다: " << output_file << "\n";
    }
    else {
        std::cout << output.str();
    }

    return 0;
}
