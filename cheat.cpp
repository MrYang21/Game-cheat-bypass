#include <iostream>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstring>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstdlib>
#include <vector>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <functional>

bool debug_enabled = true;

std::vector<uint8_t> stringToHex(const std::string &str)
{
    std::vector<uint8_t> hex_bytes;
    std::istringstream iss(str);
    std::string byte_str;
    while (iss >> byte_str)
    {
        unsigned int byte;
        std::istringstream(byte_str) >> std::hex >> byte;
        hex_bytes.push_back(static_cast<uint8_t>(byte));
    }
    return hex_bytes;
}

uintptr_t getBaseAddress(pid_t pid, const std::string &library_name)
{
    uintptr_t base_address = 0;
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps(maps_path);

    if (!maps.is_open())
    {
        if (debug_enabled)
            std::cerr << "无法打开 maps 文件: " << maps_path << std::endl;
        return 0;
    }

    std::string line;
    bool library_found = false;
    while (std::getline(maps, line))
    {
        if (line.find(library_name) != std::string::npos)
        {
            std::stringstream ss(line);
            std::string address_str;
            ss >> address_str;

            try
            {
                base_address = std::stoull(address_str, nullptr, 16);
                library_found = true;
                if (debug_enabled)
                    std::cout << "找到库: " << library_name << " 基地址: " << std::hex << base_address << std::dec << std::endl;
                break;
            }
            catch (const std::invalid_argument &e)
            {
                if (debug_enabled)
                    std::cerr << "无法解析地址: " << address_str << std::endl;
            }
        }
    }

    if (!library_found && debug_enabled)
    {
        std::cerr << "无法找到库 " << library_name << " 的基地址" << std::endl;
    }

    return base_address;
}

struct Patch
{
    uintptr_t offset;
    std::vector<uint8_t> value;
};

bool isProcessRunning(pid_t pid)
{
    std::string proc_path = "/proc/" + std::to_string(pid);
    struct stat stat_buf;
    return (stat(proc_path.c_str(), &stat_buf) == 0);
}

bool patchMemory(pid_t pid, const std::vector<Patch> &patches, uintptr_t base_address)
{
    std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(mem_path.c_str(), O_RDWR);
    if (fd < 0)
    {
        if (debug_enabled)
            std::cerr << "无法打开进程内存文件 PID " << pid << std::endl;
        return false;
    }

    auto close_fd = [&]()
    { close(fd); };                             // 使用 lambda 进行文件关闭处理
    std::vector<std::function<void()>> cleanup; // 用于存储清理任务
    cleanup.push_back(close_fd);

    for (const auto &patch : patches)
    {
        uintptr_t patch_address = base_address + patch.offset;
        if (debug_enabled)
            std::cout << "正在hook函数: " << std::hex << "隐藏" << std::endl;

        if (lseek(fd, patch_address, SEEK_SET) == -1)
        {
            if (debug_enabled)
                std::cerr << "无法跳转到地址: " << patch_address << std::endl;
            continue;
        }

        if (write(fd, patch.value.data(), patch.value.size()) != static_cast<ssize_t>(patch.value.size()))
        {
            if (debug_enabled)
                std::cerr << "写入补丁失败，偏移: " << patch.offset << std::endl;
        }
    }

    close(fd);
    return true;
}

int get_process_pid(const char *package_name)
{
    int pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[64];
    char cmdline[64];
    struct dirent *entry;
    dir = opendir("/proc");
    while ((entry = readdir(dir)) != NULL)
    {
        pid = atoi(entry->d_name);
        if (pid != 0)
        {
            sprintf(filename, "/proc/%d/cmdline", pid);
            fp = fopen(filename, "r");
            if (fp)
            {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(package_name, cmdline) == 0)
                {
                    return pid;
                }
            }
        }
    }

    closedir(dir);
    return -1;
}

void pause_process(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        if (debug_enabled)
            std::cerr << "无法暂停进程：" << pid << std::endl;
        return;
    }
    waitpid(pid, NULL, WUNTRACED);
    if (debug_enabled)
        std::cout << "进程 " << pid << " 已暂停。" << std::endl;
}

void resume_process(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        if (debug_enabled)
            std::cerr << "无法恢复进程：" << pid << std::endl;
        return;
    }
    if (debug_enabled)
        std::cout << "进程 " << std::dec << pid << " 已恢复。" << std::endl;
}

void startGameActivity(const char *packageName, const char *activityName)
{
    char cmd[128];
    sprintf(cmd, "pm path %s > /dev/null 2>&1", packageName);
    if (system(cmd) != 0)
    {
        printf("%s未安装游戏,或者程序无法启动,尝试关闭Selinux.建议手动打开当前游戏\n", packageName);
    }
    sprintf(cmd, "am start %s/%s > /dev/null 2>&1", packageName, activityName);
    system(cmd);
}

void start_game(int choice, std::string &package_name)
{
    const std::vector<std::pair<std::string, std::string>> games = {
        {"com.tencent.ig", "com.epicgames.ue4.SplashActivity"},
        {"com.pubg.krmobile", "com.epicgames.ue4.SplashActivity"},
        {"com.rekoo.pubgm", "com.epicgames.ue4.SplashActivity"},
        {"com.vng.pubgmobile", "com.epicgames.ue4.SplashActivity"}};

    if (choice < 1 || choice > 4)
    {
        std::cout << "无效选择，请输入 1 到 4 之间的数字。\n";
        exit(1);
    }

    package_name = games[choice - 1].first;
    startGameActivity(package_name.c_str(), games[choice - 1].second.c_str());
}

bool applyPatches(pid_t pid, uintptr_t base_address, const std::vector<Patch> &patches, const char *library_name)
{
    if (!patchMemory(pid, patches, base_address))
    {
        std::cerr << library_name << " 补丁应用失败。" << std::endl;
        return false;
    }
    return true;
}

void run_cheat(int choice)
{
    std::string package_name;

    // 获取游戏进程 PID，检查是否已经在运行
    start_game(choice, package_name); // 启动游戏
    pid_t pid = get_process_pid(package_name.c_str());

    if (pid != -1)
    {
        std::cerr << "检测到游戏进程 " << pid << " 正在运行，程序将退出。" << std::endl;
        return;
    }

    pid = -1;
    while (pid == -1)
    {
        pid = get_process_pid(package_name.c_str());
        if (pid == -1)
        {
            std::cerr << "未能找到游戏进程，等待中...\n";
        }
    }
    sleep(2);

    // 暂停游戏进程
    pause_process(pid);
    if (debug_enabled)
        std::cout << "暂停游戏进程 " << pid << "...\n";

    // 获取库的基地址并进行补丁操作
    const char *library_name_anogs = "libanogs.so";
    uintptr_t base_address_anogs = getBaseAddress(pid, library_name_anogs);
    if (base_address_anogs == 0)
        return;

    const char *library_name_ue4 = "libUE4.so";
    uintptr_t base_address_ue4 = getBaseAddress(pid, library_name_ue4);
    if (base_address_ue4 == 0)
        return;

    const char *library_name_anort = "libanort.so";
    uintptr_t base_address_anort = getBaseAddress(pid, library_name_anort);
    if (base_address_anort == 0)
        return;

    // 应用补丁
    std::vector<Patch> patches = {
        // { 0x, stringToHex("") },
    };

    std::vector<Patch> patchess = {
        // { 0x, stringToHex("") },
    };

    std::vector<Patch> patchesss = {
        // { 0x, stringToHex("") },
    };

    if (!applyPatches(pid, base_address_anogs, patches, library_name_anogs))
        return;
    if (!applyPatches(pid, base_address_ue4, patchess, library_name_ue4))
        return;
    if (!applyPatches(pid, base_address_anort, patchesss, library_name_anort))
        return;

    // 功能菜单
    while (true)
    {
        int action;
        std::cout << "\n功能菜单:\n";
        std::cout << "1. or广角\n";
        std::cout << "2. or广角+半火\n";
        std::cout << "请输入数字 (1 或 2): ";
        std::cin >> action;

        switch (action)
        {
        case 1:
            std::cout << "选择了 or广角\n";
            resume_process(pid);
            break;
        case 2:
            std::cout << "选择了 or广角+半火\n";
            resume_process(pid);
            break;
        default:
            std::cout << "无效选择，请输入 1 或 2。\n";
        }

        if (action == 1 || action == 2)
        {
            break;
        }
    }
}
