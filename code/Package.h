#ifndef CODE_PACKAGE_H
#define CODE_PACKAGE_H

#include <string>

class Package {
private:

public:
    Package(uint32_t src, uint32_t dst, std::string &data, bool MF,\
            uint16_t offset);
};


#endif //CODE_PACKAGE_H
