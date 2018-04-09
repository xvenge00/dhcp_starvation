cmake_minimum_required(VERSION 3.9)
project(dhcp_starvation)

set(CMAKE_C_STANDARD 99)

add_executable(starve ipk-dhcpstarve.c ipk-dhcpstarve.h)
