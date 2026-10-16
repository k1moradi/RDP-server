# SPDX-License-Identifier: GPL-3.0-or-later
# Real downstream consumer smoke test; always configure under build/consumer.
cmake_minimum_required(VERSION 3.22)
project(rdp_protocol_installed_consumer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(RDPServerProtocol CONFIG REQUIRED)
add_executable(rdp_protocol_consumer smoke.cpp)
target_link_libraries(rdp_protocol_consumer PRIVATE RDPServer::protocol)
enable_testing()
add_test(NAME install.protocol-consumer COMMAND rdp_protocol_consumer)
