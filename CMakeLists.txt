cmake_minimum_required(VERSION 3.9)
project(example VERSION 1.0.0)
include(CMakeGlobalSettings.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(BUILD_STATIC_LIBS "Build the static library" ON)
option(BUILD_SHARED_LIBS "Build the shared library" OFF)

### setup boost
find_package(Boost COMPONENTS atomic system date_time regex timer chrono log thread filesystem program_options random REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

include_directories(SYSTEM "libtorrent/include")

add_subdirectory(src)
