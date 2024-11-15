#include <iostream>
#include "cheat.h"

int main() {
    int choice;
    std::cout << "请选择要保护的游戏:\n";
    std::cout << "1. (全球)\n";
    std::cout << "2. (日韩)\n";
    std::cout << "3. (台湾)\n";
    std::cout << "4. (越南)\n";
    std::cout << "请输入数字 (1-4): ";
    
    std::cin >> choice;

    run_cheat(choice);

    return 0;
}
