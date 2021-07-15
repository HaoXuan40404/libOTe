#project(SimplestOT  C C++ ASM)

enable_language(ASM)

# set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -no-pie")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -no-pie")
# SET(CMAKE_EXE_LINKER_FLAGS "-no-pie")
SET(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -no-pie")
file(GLOB_RECURSE SRC_SIMPLE_LIB
	${CMAKE_SOURCE_DIR}/SimplestOT/*.c
	${CMAKE_SOURCE_DIR}/SimplestOT/*.s)
# message("src list ${SRC_SIMPLE_LIB}")
# add_library(SimplestOT STATIC ${SRC_SIMPLE_LIB})
add_library(SimplestOT ${SRC_SIMPLE_LIB})
# add_compile_options(SimplestOT -fPIC)
add_compile_options(-fPIC no-pie)
# target_compile_options(SimplestOT PRIVATE
#     $<$<COMPILE_LANGUAGE:ASM>:-x assembler-with-cpp ${ASM_FLAGS} -no-pie>
# )

# add_library(SimplestOT SHARED ${SRC_SIMPLE_LIB})
target_link_libraries(SimplestOT PUBLIC cryptoTools)
# target_link_libraries(SimplestOT PUBLIC SHARED cryptoTools)
# target_compile_options(SimplestOT PUBLIC -fPIC -no-pie)
target_link_options(SimplestOT PUBLIC -fPIC -no-pie)
# target_link_options(SimplestOT PUBLIC -fPIC)

#############################################
#            Install                        #
#############################################

# install library
install(TARGETS SimplestOT DESTINATION lib)

# install headers
install(DIRECTORY . DESTINATION include/SimplestOT FILES_MATCHING PATTERN "*.h")
