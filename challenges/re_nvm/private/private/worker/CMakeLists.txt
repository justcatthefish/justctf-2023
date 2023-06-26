cmake_minimum_required(VERSION 3.21)

project(worker)

add_compile_options("-fno-stack-protector")
add_compile_options("-no-pie")
add_compile_options("-O0")
# add_compile_options("-fno-elide-constructors")
add_compile_options("-fno-exceptions")


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -s")

add_subdirectory(src)
