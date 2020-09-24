cmake_minimum_required(VERSION 3.12)

project(asc_converter CXX)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE Debug CACHE STRING
          "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
          FORCE)
    endif()
endif()

# Configuration

include(cmake/pcapng.cmake)
add_subdirectory(vector_asc)

add_executable(asc_converter "src/app.cpp" "src/endianness.h")
target_link_libraries(asc_converter light_pcapng_static)
target_link_libraries(asc_converter Vector_ASC)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Testing
    include(CTest)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    
    list(APPEND asc_tests "events/CanError")
    list(APPEND asc_tests "events/CanErrorFrame")
    list(APPEND asc_tests "events/CanExtendedMessage")
    list(APPEND asc_tests "events/CanFdMessage")
    list(APPEND asc_tests "events/CanRemoteFrame")
    list(APPEND asc_tests "events/CanMessage")
    list(APPEND asc_tests "events/CanFdErrorFrame")
    list(APPEND asc_tests "events/EthernetPacket")
    list(APPEND asc_tests "events/EthernetRxError")

    foreach(asc_test ${asc_tests})
        get_filename_component(param ${asc_test} NAME)
        string(REPLACE "/" "." param ${asc_test})
        add_test(
            NAME "convert.${param}"
            COMMAND asc_converter 
                "${CMAKE_CURRENT_LIST_DIR}/vector_asc/vector_asc/src/Vector/ASC/tests/unittests/${asc_test}.asc"
                "${CMAKE_CURRENT_LIST_DIR}/tests/results/${asc_test}.pcapng"
        )
    endforeach()

endif()
