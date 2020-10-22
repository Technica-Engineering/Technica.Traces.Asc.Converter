cmake_minimum_required(VERSION 3.12)

# dependencies: Threads
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# dependencies: FLEX
if (WIN32)
    include(FetchContent)
    FetchContent_Declare(
        flex
        URL https://github.com/lexxmark/winflexbison/releases/download/v2.5.23/win_flex_bison-2.5.23.zip
    )
    FetchContent_MakeAvailable(flex)
    list(APPEND CMAKE_PREFIX_PATH  "${flex_SOURCE_DIR}")
    set(FLEX_FLAGS "--wincompat")
endif()
find_package(FLEX 2.6 REQUIRED)

# source files
flex_target(Lexer "vector_asc/src/Vector/ASC/Lexer.l" ${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp COMPILE_FLAGS ${FLEX_FLAGS})
file(GLOB ASC_SOURCES "vector_asc/src/Vector/ASC/*.cpp")

# Vector_ASC do not define a static target, so we create our own
add_library(Vector_ASC STATIC ${ASC_SOURCES} ${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp)

target_include_directories(Vector_ASC PUBLIC "." "vector_asc/src" ${FLEX_INCLUDE_DIRS})
