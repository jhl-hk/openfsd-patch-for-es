cmake_minimum_required(VERSION 3.30)
project(EuroscopePatch)

set(CMAKE_CXX_STANDARD 20)

add_definitions(-DWIN32_LEAN_AND_MEAN)
add_definitions(-DWINVER=0x0601)
add_definitions(-D_WIN32_WINNT=0x0601)
find_package(fmt CONFIG REQUIRED)

add_library(EuroscopePatch SHARED
        src/EuroScopePlugIn.h

        src/main.cpp
        src/VATSIMAuthPatch.cpp
        src/VATSIMAuthPatch.h
)

target_link_directories(EuroscopePatch PRIVATE ./)

target_link_libraries(EuroscopePatch PRIVATE
        fmt::fmt
        EuroScopePlugInDll
)