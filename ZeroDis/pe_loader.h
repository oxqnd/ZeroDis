#pragma once
#include <cstdint>
#include <vector>
#include <string>

bool load_text_section(const std::string& filename, std::vector<uint8_t>& out, uint64_t& base_address);
