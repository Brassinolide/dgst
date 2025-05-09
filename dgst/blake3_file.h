#pragma once
#include <string>
#include <filesystem>

std::string blake3_file(const std::filesystem::path& filename);
