cmake_minimum_required(VERSION 3.24) 
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_C_COMPILER "/usr/bin/gcc")
set(CMAKE_CXX_COMPILER "/usr/bin/g++")

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -g")
add_definitions(-DELPP_THREAD_SAFE)
# set the project name 
project(Client) 

add_link_options(-lpthread -lz -lm -ldl -lssl -lcrypto )
# add the executable 

aux_source_directory(. DIR_SRCS)

add_executable(Client ${DIR_SRCS}) 