cmake_minimum_required(VERSION 3.13)
project(digitalocean_dns_updater C)

set(CMAKE_C_STANDARD 11)

add_executable(digitalocean_dns_updater main.c)