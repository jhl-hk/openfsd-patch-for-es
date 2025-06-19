cmake_minimum_required(VERSION 3.20)  # Lowered for better compatibility
project(EuroscopePatch VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)

add_definitions(-DWIN32_LEAN_AND_MEAN)
add_definitions(-DWINVER=0x0601)
add_definitions(-D_WIN32_WINNT=0x0601)

find_package(fmt CONFIG REQUIRED)

# Check if EuroScope library exists
set(EUROSCOPE_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/EuroScopePlugInDll.lib")
set(EUROSCOPE_LIB_EXISTS FALSE)

if(EXISTS "${EUROSCOPE_LIB_PATH}")
    set(EUROSCOPE_LIB_EXISTS TRUE)
    message(STATUS "Found EuroScopePlugInDll.lib")
else()
    message(WARNING "EuroScopePlugInDll.lib not found at ${EUROSCOPE_LIB_PATH}")
    message(WARNING "Plugin will compile but may not link properly without EuroScope SDK")
endif()

add_library(EuroscopePatch SHARED
    src/EuroScopePlugIn.h
    src/main.cpp
    src/VATSIMAuthPatch.cpp
    src/VATSIMAuthPatch.h
)

target_link_directories(EuroscopePatch PRIVATE ./)

# Conditional linking based on library availability
if(EUROSCOPE_LIB_EXISTS)
    target_link_libraries(EuroscopePatch PRIVATE
        fmt::fmt
        EuroScopePlugInDll
    )
    message(STATUS "Linking with EuroScopePlugInDll")
else()
    target_link_libraries(EuroscopePatch PRIVATE
        fmt::fmt
    )
    message(WARNING "Building without EuroScopePlugInDll - manual linking required")
endif()

# Add compiler flags for better compatibility
target_compile_definitions(EuroscopePatch PRIVATE
    WIN32_LEAN_AND_MEAN
    WINVER=0x0601
    _WIN32_WINNT=0x0601
)
