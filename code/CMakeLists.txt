cmake_minimum_required(VERSION 3.7)
project(code)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp Sniffer.cpp Sniffer.h Assembler.cpp Assembler.h Parser.cpp Parser.h Package.cpp Package.h)
add_executable(code ${SOURCE_FILES})