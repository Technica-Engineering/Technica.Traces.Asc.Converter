
if (WIN32)
    include(FetchContent)
    FetchContent_Declare(
        flex
        URL https://github.com/lexxmark/winflexbison/releases/download/v2.5.23/win_flex_bison-2.5.23.zip
    )
    FetchContent_MakeAvailable(flex)

    set(FLEX_FLAGS "--wincompat")
    set(FLEX_DIR "${flex_SOURCE_DIR}")
endif()

if (APPLE)
    # On macOS, search Homebrew for keg-only versions of Bison and Flex. Xcode does
    # not provide new enough versions for us to use.
    execute_process(
        COMMAND brew --prefix flex 
        RESULT_VARIABLE BREW_FLEX
        OUTPUT_VARIABLE BREW_FLEX_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (BREW_FLEX EQUAL 0 AND EXISTS "${BREW_FLEX_PREFIX}")
        message(STATUS "Found Flex keg installed by Homebrew at ${BREW_FLEX_PREFIX}")
        set(FLEX_DIR "${BREW_FLEX_PREFIX}")
    endif()
endif()
