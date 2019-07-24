cmake_minimum_required(VERSION 2.8.12)

project(vzcpuidctl)

add_compile_options(-DCONFIG_X86_64)
add_compile_options(-D_FILE_OFFSET_BITS=64)
add_compile_options(-D_GNU_SOURCE)
add_compile_options(-Wall -Wformat-security)
add_compile_options(-iquote src/include/)

include_directories(src/include)


set_source_files_properties(tags PROPERTIES GENERATED true)
add_custom_target(tags
	COMMAND ctags -R .
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

set(SOURCES
	"src/cpu.c"
	"src/log.c"
	"src/base64.c"
	"src/vzcpuidctl.c"
	"src/main.c")

set(HEADERS
	"src/include/base64.h"
	"src/include/bitops.h"
	"src/include/compiler.h"
	"src/include/cpu.h"
	"src/include/err.h"
	"src/include/log.h"
	"src/include/list.h"
	"src/include/vzcpuidctl.h"
	"src/include/xmalloc.h")

add_executable(vzcpuidctl ${SOURCES} ${HEADERS})
