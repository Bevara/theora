cmake_minimum_required(VERSION 3.7)
project(Filters)

include(filters.cmake)

add_definitions(-fpic)

SET(THEORA_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/dec_theora.c
)

SET(THEORA_INCLUDE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

SET(THEORA_LIB
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libtheora.a
        #${THIRD_PARTIES_BINARIES}/vorbis/lib/libvorbis.a
        #${THIRD_PARTIES_BINARIES}/ogg/libogg.a
)

SET(THEORA_FLAG
        GPAC_HAS_THEORA
)

add_filter(theora
        "${THEORA_SRC}"
        "${THEORA_LIB}"
        []
        "${THEORA_FLAG}"
        "${THEORA_INCLUDE}"
        ""
        "1")
