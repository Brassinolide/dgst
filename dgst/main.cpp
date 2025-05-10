#pragma execution_character_set("utf-8")
#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
#include <mutex>
#include <queue>
#include <locale>
#include <codecvt>
#include <unordered_set>
#include "blake3_file.h"
#include "args.hxx"
#include "literals.h"
#include "json.hpp"
#include "utfcpp/utf8.h"
#include "termcolor.hpp"
#include "BS_thread_pool.hpp"

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

#define CRITICAL_ERROR(statement) do {\
    std::cerr << termcolor::red; \
    statement; \
    std::cerr << termcolor::reset << std::endl; \
    system("pause>nul");\
    exit(1);\
} while (0)

namespace myfs {
    std::optional<std::filesystem::path> safe_parse(const std::string& path_str_utf8) {
        try {
            std::filesystem::path path_fs(std::filesystem::u8path(path_str_utf8));
            return path_fs;
        }
        catch (const std::filesystem::filesystem_error& e) {
            return std::nullopt;
        }
    }

    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> EnumerateFiles(const std::filesystem::path& root_path) {
        std::vector<std::pair<std::filesystem::path, std::filesystem::path>> files;
        files.reserve(5_KiB);

        try {
            bool skipped_dgst = false;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root_path)) {
                if (entry.is_regular_file()) {
                    const auto& full_path = entry.path();
                    const auto& relative_path = full_path.lexically_relative(root_path);

                    if (!skipped_dgst && relative_path == "dgst.json") {
                        skipped_dgst = true;
                        continue;
                    }

                    files.push_back({ full_path, relative_path });
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            std::cerr << termcolor::red << e.what() << termcolor::reset << std::endl;
        }

        return files;
    }

    using EnumCallback = std::function<void(const std::filesystem::path&, const std::filesystem::path&)>;
    void EnumerateFilesCallback(const std::filesystem::path& root_path, const EnumCallback& callback) {
        try {
            bool skipped_dgst = false;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root_path)) {
                if (entry.is_regular_file()) {
                    const auto& full_path = entry.path();
                    const auto& relative_path = full_path.lexically_relative(root_path);

                    if (!skipped_dgst && relative_path == "dgst.json") {
                        skipped_dgst = true;
                        continue;
                    }

                    callback(full_path, relative_path);
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            std::cerr << termcolor::red << e.what() << termcolor::reset << std::endl;
        }
    }

    void EnumerateFilesCallbackThreadPool(const std::filesystem::path& root_path, const EnumCallback& callback, BS::thread_pool<>& pool) {
        EnumerateFilesCallback(root_path, [&](const std::filesystem::path& full_path, const std::filesystem::path& relative_path) {
            pool.submit_task([=]() { callback(full_path, relative_path); });
            });
        pool.wait();
    }

    std::string fspath_to_utf8(const std::filesystem::path& p) {
        std::string utf8;
        const std::wstring& utf16 = p.wstring();
        utf8::utf16to8(utf16.begin(), utf16.end(), std::back_inserter(utf8));
        return utf8;
    }
};

class mytimer {
private:
    std::chrono::high_resolution_clock::time_point _begin;
public:
    mytimer() { update(); }

    void update() {
        _begin = std::chrono::high_resolution_clock::now();
    }

    double get_seconds() const {
        return std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - _begin).count();
    }

    double get_milliseconds() const {
        return std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - _begin).count();
    }

    double get_microseconds() const {
        return std::chrono::duration<double, std::micro>(std::chrono::high_resolution_clock::now() - _begin).count();
    }

    double get_nanoseconds() const {
        return std::chrono::duration<double, std::nano>(std::chrono::high_resolution_clock::now() - _begin).count();
    }
};

enum class ParseStatus {
    OK,
    INVALID_JSON_STRUCTURE,
    SECURITY_VIOLATION
};
std::pair<ParseStatus, std::optional<json>> safe_parse_dgst(std::ifstream& dgst_io) {
    try {
        json test = json::parse(dgst_io);
        if (!(test.contains("alg") && test.contains("dgst") && test["alg"].is_string() && test["dgst"].is_object())) {
            return { ParseStatus::INVALID_JSON_STRUCTURE, std::nullopt };
        }

        for (const auto& [key, value] : test["dgst"].items()) {
            if (!value.is_string()) {
                return { ParseStatus::INVALID_JSON_STRUCTURE, std::nullopt };
            }

            std::filesystem::path path(std::filesystem::u8path(key));

            if (path.is_absolute()) {
                return { ParseStatus::SECURITY_VIOLATION, std::nullopt };
            }

            for (const auto& part : path) {
                if (part == "..") {
                    return { ParseStatus::SECURITY_VIOLATION, std::nullopt };
                }
            }
        }

        return { ParseStatus::OK, test};
    }
    catch (const nlohmann::json::exception& e) {
        return { ParseStatus::INVALID_JSON_STRUCTURE, std::nullopt };
    }
}

static void full_add(const std::filesystem::path& working_path, const std::filesystem::path& dgst_path) {
    json result;
    result["alg"] = "blake3";
    std::atomic<uint64_t> counter = 0;

    BS::thread_pool pool(std::max(1u, std::thread::hardware_concurrency() / 2 - 2));

    std::mutex json_mutex;
    myfs::EnumerateFilesCallbackThreadPool(working_path,
        [&result, &counter, &json_mutex](const std::filesystem::path& full_path, const std::filesystem::path& relative_path) {
            counter++;
            const std::string& relative_path_utf8 = myfs::fspath_to_utf8(relative_path);
            const std::string& hash = blake3_file(full_path);

            std::lock_guard lock(json_mutex);
            result["dgst"][relative_path_utf8] = hash;
        }, pool);

    if (counter) {
        std::ofstream dgst_io(dgst_path, std::ios::trunc);
        if (dgst_io.good()) {
            dgst_io << result.dump(4) << std::endl;
            dgst_io.close();
        }
        else {
            std::cerr << termcolor::red << "无法写到文件，输出到控制台" << termcolor::reset << std::endl;
            std::cout << result.dump(4) << std::endl;
        }
    }
    std::cout << "共遍历文件数：" << counter << std::endl;
}

static void increment_add(const std::filesystem::path& working_path, const std::filesystem::path& dgst_path, const json& increment) {
    json result = increment;
    std::atomic<uint64_t> counter_add = 0, counter_dec = 0;
    std::unordered_set<std::string> traversed_files_relative_path_utf8;
    traversed_files_relative_path_utf8.reserve(1_KiB);

    BS::thread_pool pool(std::max(1u, std::thread::hardware_concurrency() / 2 - 2));

    std::mutex json_mutex;
    std::mutex insert_mutex;
    myfs::EnumerateFilesCallbackThreadPool(working_path,
        [&result, &counter_add, &traversed_files_relative_path_utf8, &json_mutex, &insert_mutex](const std::filesystem::path& full_path, const std::filesystem::path& relative_path) {
            const std::string& relative_path_utf8 = myfs::fspath_to_utf8(relative_path);

            if (!result["dgst"].contains(relative_path_utf8)) {
                counter_add++;
                const std::string& hash = blake3_file(full_path);

                std::lock_guard lock(json_mutex);
                result["dgst"][relative_path_utf8] = hash;
                std::cout << termcolor::green << " + " << relative_path_utf8 << termcolor::reset << std::endl;
            }

            std::lock_guard lock(insert_mutex);
            traversed_files_relative_path_utf8.insert(relative_path_utf8);
        }, pool);

    std::vector<std::string> to_delete;
    for (const auto& [key, value] : result["dgst"].items()) {
        if (traversed_files_relative_path_utf8.find(key) == traversed_files_relative_path_utf8.end()) {
            to_delete.push_back(key);
        }
    }

    for (const auto& key : to_delete) {
        std::cout << termcolor::yellow << " - " << key << termcolor::reset << std::endl;
        counter_dec++;
        result["dgst"].erase(key);
    }

    if (counter_add || counter_dec) {
        std::ofstream dgst_file(dgst_path, std::ios::trunc);
        if (dgst_file.good()) {
            dgst_file << result.dump(4) << std::endl;
            dgst_file.close();
        }
        else {
            std::cerr << termcolor::red << "无法写到文件，输出到控制台" << termcolor::reset << std::endl;
            std::cout << result.dump(4) << std::endl;
        }
    }
    std::cout << "共增量文件：" << counter_add << "\n共减量文件：" << counter_dec << std::endl;
}

void verify(const std::filesystem::path& working_path, const json& dgst) {
    std::atomic<uint64_t> counter_total{ 0 }, counter_passed{ 0 }, counter_notfound{ 0 }, counter_notpassed{ 0 };

    BS::thread_pool pool(std::max(1u, std::thread::hardware_concurrency() / 2 - 2));
    
    std::mutex cout_mutex;
    for (const auto& [key, value] : dgst["dgst"].items()) {
        counter_total++;

        pool.submit_task([&, key]() {
            std::filesystem::path full_path = (working_path / std::filesystem::u8path(key)).lexically_normal();

            if (!std::filesystem::exists(full_path)) {
                counter_notfound++;
                std::lock_guard lock(cout_mutex);
                std::cout << termcolor::yellow << "文件未找到：" << key << termcolor::reset << std::endl;
                return;
            }

            if (dgst["dgst"][key] != blake3_file(full_path)) {
                counter_notpassed++;
                std::lock_guard lock(cout_mutex);
                std::cout << termcolor::red << "验证失败：" << key << termcolor::reset << std::endl;
                return;
            }

            counter_passed++;
            });
    }

    pool.wait();

    uint64_t counter_newfile = 0;
    uint64_t coutner_enum = 0;
    myfs::EnumerateFilesCallback(working_path,
        [&dgst, &counter_newfile, &coutner_enum](const std::filesystem::path& full_path, const std::filesystem::path& relative_path) {
            const std::string& relative_path_utf8 = myfs::fspath_to_utf8(relative_path);
            coutner_enum++;

            if (!dgst["dgst"].contains(relative_path_utf8)) {
                counter_newfile++;
                std::cout << termcolor::magenta << "新文件：" << relative_path_utf8 << termcolor::reset << std::endl;
            }
        });

    std::cout << "记录文件数：" << counter_total << "\n遍历文件数：" << coutner_enum << std::endl;
    if (counter_passed) {
        std::cout << termcolor::green << "验证通过：" << counter_passed << termcolor::reset << std::endl;
    }
    if (counter_notfound) {
        std::cout << termcolor::yellow << "文件未找到：" << counter_notfound << termcolor::reset << std::endl;
    }
    if (counter_newfile) {
        std::cout << termcolor::magenta << "新文件：" << counter_newfile << termcolor::reset << std::endl;
    }
    if (counter_notpassed) {
        std::cout << termcolor::red << "验证失败：" << counter_notpassed << termcolor::reset << std::endl;
    }
}

int mymain(int argc, char** argv_utf8) {
    args::ArgumentParser parser("dgst");

    args::Group commands(parser, "工作模式");
    args::Command cmd_add(commands, "a", "添加dgst");
    args::Flag flag_force(cmd_add, "force", "当 dgst.json 存在时也强制进行全添加", { 'f', "force" });
    args::Command cmd_verify(commands, "v", "验证dgst");

    args::Group arguments(parser, "参数", args::Group::Validators::DontCare, args::Options::Global);
    args::HelpFlag arg_help(arguments, "help", "显示帮助信息", { 'h', "help" });
    args::Positional<std::string> arg_working_path(arguments, "path", "路径", args::Options::Required);

    try {
        parser.ParseCLI(argc, argv_utf8);
    }
    catch (args::Help) {
        std::cout << parser;
        return 0;
    }
    catch (args::Error e) {
        std::cerr << termcolor::red << e.what() << termcolor::reset << std::endl;
        std::cerr << parser;
        return 1;
    }

    std::optional<json> parsed_working_path = myfs::safe_parse(arg_working_path.Get());
    if (!parsed_working_path) {
        CRITICAL_ERROR(std::cerr << "请输入正确的路径");
    }

    const std::filesystem::path& working_path = parsed_working_path.value();
    if (std::filesystem::is_regular_file(working_path)) {
        std::cout << "文件：" << working_path << std::endl << "Blake3：" << blake3_file(working_path);
    }
    else if (std::filesystem::is_directory(working_path)) {
        if (cmd_add) {
            std::cout << "添加";
        }
        else {
            std::cout << "验证";
        }
        std::cout << ' ' << working_path << std::endl;

        mytimer timer;
        timer.update();

        std::filesystem::path dgst_path = working_path / std::filesystem::u8path("dgst.json");
        if (cmd_add) {
            if (std::filesystem::exists(dgst_path)) {
                std::cout << "dgst.json 已存在，默认使用增量添加，除非指定了 -f 或 --force 选项" << std::endl;

                bool bad_dgst = false;

                std::ifstream dgst_io(dgst_path);
                if (!dgst_io.good()) {
                    std::cerr << termcolor::red << "无法读取 dgst.json，将重新创建" << termcolor::reset << std::endl;
                    bad_dgst = true;
                }

                json parsed_dgst;
                if (!bad_dgst) {
                    const auto& [parse_status, parsed_data] = safe_parse_dgst(dgst_io);
                    if (parse_status == ParseStatus::INVALID_JSON_STRUCTURE) {
                        std::cerr << termcolor::red << "dgst.json 结构损坏，将重新创建" << termcolor::reset << std::endl;
                        bad_dgst = true;
                    }
                    else if (parse_status == ParseStatus::SECURITY_VIOLATION) {
                        std::cerr << termcolor::red << "dgst.json 存在恶意攻击行为（可能是目录逃逸），将重新创建" << termcolor::reset << std::endl;
                        bad_dgst = true;
                    }
                    else {
                        parsed_dgst = parsed_data;
                    }
                }

                if (bad_dgst || flag_force) {
                    full_add(working_path, dgst_path);
                }
                else {
                    increment_add(working_path, dgst_path, parsed_dgst);
                }
            }
            else {
                full_add(working_path, dgst_path);
            }
        }
        else {
            if (!std::filesystem::exists(dgst_path)) {
                CRITICAL_ERROR(std::cerr << "dgst.json 不存在，请先添加");
            }

            std::ifstream dgst_io(dgst_path);
            if (!dgst_io.good()) {
                CRITICAL_ERROR(std::cerr << "无法读取 dgst.json");
            }

            json parsed_dgst;

            const auto& [parse_status, parsed_data] = safe_parse_dgst(dgst_io);
            if (parse_status == ParseStatus::INVALID_JSON_STRUCTURE) {
                CRITICAL_ERROR(std::cerr << "dgst.json 结构损坏");
            }
            else if (parse_status == ParseStatus::SECURITY_VIOLATION) {
                CRITICAL_ERROR(std::cerr << "dgst.json 存在恶意攻击行为（可能是目录逃逸），请检查");
            }
            else {
                parsed_dgst = parsed_data;
            }

            verify(working_path, parsed_dgst);
        }
        std::cout << "用时：" << timer.get_milliseconds() << " 毫秒";
    }
    else {
        CRITICAL_ERROR(std::cerr << "请输入正确的路径");
    }

    std::cout << termcolor::reset << std::endl;
    system("pause");
    return 0;
}

#ifdef _WIN32
#include <windows.h>

int wmain(int argc, wchar_t** argv) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetConsoleTitleW(L"dgst");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    char** argv_utf8 = new char*[argc];

    for (int i = 0; i < argc; ++i) {
        std::wstring arg_utf16 = argv[i];
        std::string arg_utf8;
        utf8::utf16to8(arg_utf16.begin(), arg_utf16.end(), back_inserter(arg_utf8));

        argv_utf8[i] = new char[arg_utf8.length() + 1];
        memcpy(argv_utf8[i], arg_utf8.c_str(), arg_utf8.length() + 1);
    }

    int ret = mymain(argc, argv_utf8);

    for (int i = 0; i < argc; ++i) {
        delete[] argv_utf8[i];
    }
    delete[] argv_utf8;
    return ret;
}
#else
int main(int argc, char** argv) {
    return mymain(argc, argv);
}
#endif
