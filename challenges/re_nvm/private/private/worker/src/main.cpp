#include "vm.hpp"

int main() {
    std::setbuf(stdin, nullptr);
    std::setbuf(stdout, nullptr);
    VM<uint16_t> vm;
    vm.run();
    return 0;
}
