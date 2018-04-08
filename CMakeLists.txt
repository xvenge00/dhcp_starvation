cmake_minimum_required(VERSION 3.9)
project(dhcp_starvation)

set(CMAKE_C_STANDARD 99)

add_executable(starve starve.c starve.h)
add_executable(demo demo.c demo_starve_raw.c)
add_executable(demo2 demo2.c)
add_executable(raw_starve starve_raw.c starve_raw.h)