cmake_minimum_required(VERSION 3.20)
project(ref2_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# ── ref2_ingest ────────────────────────────────────────────────────────────────
add_library(ref2_ingest OBJECT
    c/ingest/pcap_reader.c
    c/ingest/raw_reader.c
    c/ingest/plaintext_reader.c
    c/ingest/syscall_reader.c
    c/ingest/ingest_common.c)
target_include_directories(ref2_ingest PUBLIC c/ingest ${PCAP_INCLUDE_DIRS})
target_compile_options(ref2_ingest PRIVATE ${PCAP_CFLAGS_OTHER})

# ── ref2_token ─────────────────────────────────────────────────────────────────
add_library(ref2_token OBJECT
    c/token/framing.c
    c/token/length_field.c)
target_include_directories(ref2_token PUBLIC c/token c/ingest)

# ── ref2_format ────────────────────────────────────────────────────────────────
add_library(ref2_format OBJECT
    c/format/aligner.c
    c/format/cluster.c
    c/format/type_classifier.c)
target_include_directories(ref2_format PUBLIC c/format c/token c/ingest)

# ── combined libref2.a ─────────────────────────────────────────────────────────
add_library(ref2 STATIC
    $<TARGET_OBJECTS:ref2_ingest>
    $<TARGET_OBJECTS:ref2_token>
    $<TARGET_OBJECTS:ref2_format>)
target_include_directories(ref2 PUBLIC c/ingest c/token c/format)
target_link_libraries(ref2 PUBLIC ${PCAP_LIBRARIES})

set_target_properties(ref2 PROPERTIES OUTPUT_NAME ref2)

install(TARGETS ref2 DESTINATION lib)
install(FILES c/ingest/ingest.h c/token/token.h c/format/format.h
        DESTINATION include/ref2)
