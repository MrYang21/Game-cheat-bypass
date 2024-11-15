#ifndef CHEAT_H
#define CHEAT_H

#include <vector>
#include <string>
#include <cstdint>

// 字符串转换为16进制字节数组
std::vector<uint8_t> stringToHex(const std::string& str);

// 调试信息
void debug_print(const std::string& msg);

// 获取进程指定库的基地址
uintptr_t getBaseAddress(pid_t pid, const std::string& library_name);

// 内存补丁结构体
struct Patch {
    uintptr_t offset;
    std::vector<uint8_t> value;
};

// 打补丁到内存
bool patchMemory(pid_t pid, const std::vector<Patch>& patches, uintptr_t base_address);

// 获取指定包名的进程PID
pid_t get_process_pid(const std::string& package_name);

// 暂停进程
void pause_process(pid_t pid);

// 恢复进程
void resume_process(pid_t pid);

// 启动指定游戏
void start_game(int choice, std::string& package_name);

// 启动游戏程序
void startGameActivity(const char *packageName, const char *activityName);

// 运行补丁功能的主要函数
void run_cheat(int choice);

#endif // CHEAT_H
