cmake_minimum_required(VERSION 3.12)

# dependencies
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# source files
file(GLOB ASC_SOURCES "vector_asc/src/Vector/ASC/*.cpp")
# dependencies
find_package(FLEX)

# Vector_ASC do not define a static target, so we create our own
add_library(Vector_ASC STATIC ${ASC_SOURCES})
target_include_directories(Vector_ASC PUBLIC "." "vector_asc/src")
target_include_directories(Vector_ASC PUBLIC ${FLEX_INCLUDE_DIRS})
