cmake_minimum_required(VERSION 3.4.1)

set(GAME_SOURCE)

file(GLOB GAME_SOURCE "src/main/cpp/*.cpp")

#list(APPEND GAME_SOURCE
#        src/main/cpp/native-lib.cpp
#        src/main/cpp/AndroidSysInfo.cpp
#        )

add_library(native-lib SHARED ${GAME_SOURCE} )

find_library(log-lib log )

target_link_libraries(native-lib ${log-lib} )
