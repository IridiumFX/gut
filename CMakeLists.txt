cmake_minimum_required(VERSION 3.20)
project(Gut VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# --- Vendored apennines sources ---
set(VENDOR_SOURCES
    lib/apennines/c/buf.c
    lib/apennines/c/zlib_wrap.c
    lib/apennines/c/deflate.c
    lib/apennines/c/diff.c
)

# --- Gut library sources (everything except main.c) ---
file(GLOB_RECURSE GUT_ALL_SOURCES src/main/c/*.c)
list(FILTER GUT_ALL_SOURCES EXCLUDE REGEX "main\\.c$")

# --- Gut static library ---
add_library(gut_lib STATIC ${GUT_ALL_SOURCES} ${VENDOR_SOURCES})

target_include_directories(gut_lib PUBLIC
    src/main/h
    lib/apennines/h
)

target_compile_definitions(gut_lib PRIVATE GUT_BUILDING)

if(MSVC)
    target_compile_options(gut_lib PRIVATE /W4)
else()
    target_compile_options(gut_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --- Gut CLI executable ---
add_executable(gut_cli src/main/c/main.c)
target_link_libraries(gut_cli PRIVATE gut_lib)

if(MSVC)
    target_compile_options(gut_cli PRIVATE /W4)
else()
    target_compile_options(gut_cli PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(gut_cli PROPERTIES OUTPUT_NAME gut)

# --- Tests ---
file(GLOB_RECURSE TEST_SOURCES src/test/c/*.c)
if(TEST_SOURCES)
    add_executable(gut_test ${TEST_SOURCES})
    target_link_libraries(gut_test PRIVATE gut_lib)
    target_include_directories(gut_test PRIVATE src/main/h lib/apennines/h)
endif()
