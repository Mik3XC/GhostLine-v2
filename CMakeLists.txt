cmake_minimum_required(VERSION 3.16)
project(ghostline_gate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GHOSTLINE_BUILD_QT "Build the embedded Qt operator shell" ON)
set(GHOSTLINE_QT_MAJOR "AUTO" CACHE STRING "Qt major version for the operator UI: AUTO, 5, or 6")
set_property(CACHE GHOSTLINE_QT_MAJOR PROPERTY STRINGS AUTO 5 6)

add_library(ghostline_core
    src/audit.cpp
    src/builtin_plugins.cpp
    src/capture.cpp
    src/operator_state.cpp
    src/pid_search.cpp
    src/plugin_registry.cpp
    src/serial_bridge.cpp
    src/transport_core.cpp
)

target_include_directories(ghostline_core PUBLIC include)
target_compile_options(ghostline_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(ghostline_cli src/main.cpp)
target_link_libraries(ghostline_cli PRIVATE ghostline_core)

add_executable(gl src/main.cpp)
target_link_libraries(gl PRIVATE ghostline_core)

add_executable(ghostline_shell src/terminal_shell.cpp)
target_link_libraries(ghostline_shell PRIVATE ghostline_core)
target_compile_options(ghostline_shell PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(ghostline_tests tests/ghostline_tests.cpp)
target_link_libraries(ghostline_tests PRIVATE ghostline_core)
add_test(NAME ghostline_tests COMMAND ghostline_tests)
add_test(NAME ghostline_rules_loader COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/test_rules_loader.py)
if(UNIX)
    add_test(NAME ghostline_trace_containment
             COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/test_trace_containment.py $<TARGET_FILE:ghostline_cli>)
endif()

if(GHOSTLINE_BUILD_QT)
    if(GHOSTLINE_QT_MAJOR STREQUAL "5")
        find_package(Qt5 COMPONENTS Widgets REQUIRED)
        set(GHOSTLINE_QT_PACKAGE Qt5)
    elseif(GHOSTLINE_QT_MAJOR STREQUAL "6")
        find_package(Qt6 COMPONENTS Widgets REQUIRED)
        set(GHOSTLINE_QT_PACKAGE Qt6)
    else()
        find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets QUIET)
        if(QT_FOUND)
            find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)
            set(GHOSTLINE_QT_PACKAGE Qt${QT_VERSION_MAJOR})
        endif()
    endif()
    if(GHOSTLINE_QT_PACKAGE)
        if(GHOSTLINE_QT_PACKAGE STREQUAL "Qt6")
        qt_standard_project_setup()
        endif()
        add_executable(ghostline_qt src/qt_operator_main.cpp)
        target_link_libraries(ghostline_qt PRIVATE ${GHOSTLINE_QT_PACKAGE}::Widgets ghostline_core)
        target_compile_options(ghostline_qt PRIVATE -Wall -Wextra -Wpedantic)
    else()
        message(WARNING "Qt5/Qt6 Widgets not found; ghostline_qt target will not be built.")
    endif()
endif()
