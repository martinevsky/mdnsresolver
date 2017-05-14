cmake_minimum_required (VERSION 3.5)
project (mDNSResolver)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED on)

find_package  (Boost REQUIRED COMPONENTS system)

link_libraries (${Boost_LIBRARIES})
include_directories (${Boost_INCLUDE_DIRS}) 

if (WIN32)
	#©http://stackoverflow.com/questions/9742003/platform-detection-in-cmake
	macro (get_WIN32_WINNT version)
		if (WIN32 AND CMAKE_SYSTEM_VERSION)
			set(ver ${CMAKE_SYSTEM_VERSION})
			string(REPLACE "." "" ver ${ver})
			string(REGEX REPLACE "([0-9])" "0\\1" ver ${ver})

			set(${version} "0x${ver}")
		endif()
	endmacro()

	get_WIN32_WINNT(ver)
	add_definitions(-D_WIN32_WINNT=${ver})
endif()

add_executable (mDNSResolver main.cpp)