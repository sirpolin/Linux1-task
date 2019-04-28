cmake_minimum_required(VERSION 3.14)
project(Linux1_task C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

find_package (Threads)
add_executable(Linux1_task
        base64.c
        base64.h
        includes.h
        main.c
        os.h)

target_link_libraries (Linux1_task ${CMAKE_THREAD_LIBS_INIT})