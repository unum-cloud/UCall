include(FetchContent)
FetchContent_Declare(
    yyjson
    GIT_REPOSITORY https://github.com/ibireme/yyjson.git
    GIT_TAG 0.13.0
    GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL SYSTEM
)
FetchContent_MakeAvailable(yyjson)
set_property(TARGET yyjson PROPERTY POSITION_INDEPENDENT_CODE ON)
add_library(yyjson::yyjson ALIAS yyjson)
