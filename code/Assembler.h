#ifndef CODE_ASSEMBLER_H
#define CODE_ASSEMBLER_H


#include <cstdint>
#include "Package.h"

class Assembler {

public:
    void addPackage(uint16_t id, Package aPackage);
};


#endif //CODE_ASSEMBLER_H
