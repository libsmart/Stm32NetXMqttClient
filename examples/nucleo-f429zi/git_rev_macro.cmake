#
# * include this file at the end of CMakeLists_template.txt
#   `include(git_rev_macro.cmake)`
#

find_package(Python3 COMPONENTS Interpreter REQUIRED)
execute_process(
        #COMMAND Python3::Interpreter ${CMAKE_SOURCE_DIR}/git_rev_macro.py
        #COMMAND Python3::Interpreter ${PROJECT_SOURCE_DIR}/git_rev_macro.py
        #COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/git_rev_macro.py
        COMMAND python ${PROJECT_SOURCE_DIR}/git_rev_macro.py
        OUTPUT_VARIABLE GIT_REVISION_FLAGS
        OUTPUT_FILE ${PROJECT_SOURCE_DIR}/git_rev_macro.txt
        #ECHO_OUTPUT_VARIABLE
        #COMMAND_ECHO STDOUT
        RESULT_VARIABLE PROCESS_RESULT
)
if(NOT ${PROCESS_RESULT} EQUAL 0)
    message(FATAL_ERROR "Fehler beim Ausführen des Python-Skripts: ${PROCESS_RESULT}")
endif()
file(STRINGS ${PROJECT_SOURCE_DIR}/git_rev_macro.txt GIT_REVISION_FLAGS)
add_definitions(${GIT_REVISION_FLAGS})
add_custom_command(
        OUTPUT ${PROJECT_SOURCE_DIR}/git_rev_macro.txt
        COMMAND Python3::Interpreter ${CMAKE_SOURCE_DIR}/git_rev_macro.py > ${PROJECT_SOURCE_DIR}/git_rev_macro.txt
        COMMENT "Executing git_rev_macro.py to generate compiler flags"
)
add_custom_target(git_rev_macro_txt ALL
        DEPENDS ${PROJECT_SOURCE_DIR}/git_rev_macro.txt
)
add_dependencies(${PROJECT_NAME}.elf git_rev_macro_txt)
