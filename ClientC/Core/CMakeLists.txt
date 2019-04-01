# CMakeList.txt : CMake project for Core, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (Core "Core.cpp" "Core.h" "database/Database.cpp" "database/Database.h" "database/Node.cpp" "database/Node.h")

# TODO: Add tests and install targets if needed.
