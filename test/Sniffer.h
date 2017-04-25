#ifndef CODE_SNIFFER_H
#define CODE_SNIFFER_H


#include <fstream>
#include "Assembler.h"

class Sniffer {
private:
    std::ifstream packagesFile;
    Assembler assembler;
public:
    Sniffer(const char *ipPackagePath, Assembler& assembler);

    ~Sniffer();

    Sniffer(const Sniffer& other) = delete;

    Sniffer& operator=(const Sniffer& other) = delete;

    void sniffPackages();

    void sniff();
};


#endif //CODE_SNIFFER_H
