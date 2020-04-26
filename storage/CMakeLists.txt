cmake_minimum_required(VERSION 3.1)

add_library(storage STATIC
    src/Database.cpp
)

set_property(TARGET storage PROPERTY CXX_STANDARD 14)

target_include_directories(storage
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

vaizon_add_subdirectory(../common common)
target_link_libraries(storage PRIVATE common)
vaizon_add_subdirectory(../utils utils)
target_link_libraries(storage PRIVATE utils)
vaizon_add_subdirectory(../vendors/sqlite sqlite)
target_link_libraries(storage PRIVATE sqlite)


if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
	thread
        system
        filesystem
    )
endif()

target_include_directories(storage PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(storage PRIVATE ${Boost_LIBRARIES})
