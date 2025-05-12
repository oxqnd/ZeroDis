#include "instruction.h"
#include <sstream>
#include <iomanip>

std::string Instruction::toString(bool show_bytes) const {
    std::ostringstream oss;

    // 주소 출력 (0 패딩)
    oss << std::hex << std::setw(8) << std::setfill('0') << address << ": ";

    // 라벨 출력
    if (!label.empty()) {
        oss << label << ":\n";
        oss << std::setw(8) << std::setfill('0') << address << ": ";
    }

    // 명령어 바이트 출력
    if (show_bytes) {
        for (auto b : bytes) {
            oss << std::setw(2) << std::setfill('0') << std::hex << (int)b << " ";
        }
        if (bytes.size() < 6) {
            oss << std::string((6 - bytes.size()) * 3, ' ');
        }
    }
    else {
        oss << std::string(18, ' ');
    }

    // 💡 여기서 setfill(' ')로 리셋해야 문제 해결
    oss << std::setfill(' ');

    // 명령어와 피연산자 간 정렬
    oss << std::left << std::setw(10) << mnemonic;

    if (!operands.empty()) {
        oss << operands;
    }

    if (!comment.empty()) {
        oss << "    ; " << comment;
    }

    return oss.str();
}
