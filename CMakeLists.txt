cmake_minimum_required(VERSION 3.0)
project(onm-tc-acls-plugin C)

set(PLUGIN_LIBRARY_NAME srplg-onm-tc-acls)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/deps/uthash
)

set(PLUGIN 0 CACHE BOOL "Build a plugin")

set(
    SOURCES

    src/utils/memory.h
    src/utils/memory.c
    src/plugin.c
    src/plugin/ly_tree.c
    src/plugin/data/acls/acl.c
    src/plugin/data/acls/acl.h
    src/plugin/data/acls/acl/linked_list.h
    src/plugin/data/attachment_points/attachment_points.c
    src/plugin/data/attachment_points/attachment_points.h
    src/plugin/data/attachment_points/linked_list.h
    src/plugin/data/acls/acl/aces.c
    src/plugin/data/acls/acl/aces.h
    src/plugin/startup/load.c
    src/plugin/store.c
    src/plugin/running/load.c
    src/plugin/subscription/change.c
    src/plugin/subscription/operational.c
    src/plugin/subscription/rpc.c
    src/plugin/api/tcnl.c
    src/plugin/api/check.c
    src/plugin/api/load.c
    src/plugin/api/store.c
    src/plugin/api/acls/change.c
    src/plugin/api/acls/attachment-points/check.c
    src/plugin/api/acls/attachment-points/load.c
    src/plugin/api/acls/attachment-points/store.c
    src/plugin/api/acls/attachment-points/change.c
    src/plugin/api/acls/change.c
    src/plugin/api/acls/attachment-points/change.c
    src/plugin/api/acls/attachment-points/interface/change.c
    src/plugin/api/acls/attachment-points/interface/egress/acl-sets/change.c
    src/plugin/api/acls/attachment-points/interface/egress/acl-sets/acl-set/change.c
    src/plugin/api/acls/attachment-points/interface/ingress/acl-sets/change.c
    src/plugin/api/acls/attachment-points/interface/ingress/acl-sets/acl-set/change.c
    src/plugin/api/acls/acl/change.c
    src/plugin/api/acls/acl/aces/change.c
    src/plugin/api/acls/acl/aces/ace/change.c
    src/plugin/api/acls/acl/aces/ace/actions/change.c
    src/plugin/api/acls/acl/aces/ace/matches/change.c
    src/plugin/api/acls/acl/aces/ace/matches/icmp/change.c
    src/plugin/api/acls/acl/aces/ace/matches/udp/change.c
    src/plugin/api/acls/acl/aces/ace/matches/udp/destination-port/change.c
    src/plugin/api/acls/acl/aces/ace/matches/udp/source-port/change.c
    src/plugin/api/acls/acl/aces/ace/matches/tcp/change.c
    src/plugin/api/acls/acl/aces/ace/matches/tcp/destination-port/change.c
    src/plugin/api/acls/acl/aces/ace/matches/tcp/source-port/change.c
    src/plugin/api/acls/acl/aces/ace/matches/ipv6/change.c
    src/plugin/api/acls/acl/aces/ace/matches/ipv4/change.c
    src/plugin/api/acls/acl/aces/ace/matches/eth/change.c
)

# plugin library
add_library(
    ${PLUGIN_LIBRARY_NAME}
    STATIC
    ${SOURCES}
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules")
find_package(SYSREPO REQUIRED)
find_package(LIBYANG REQUIRED)
find_package(SRPC REQUIRED)
find_package(NL REQUIRED)
find_package(LIBSYSTEMD)
find_package(AUGYANG)

if(PLUGIN)
    # ignore plugin library and compile PROJECT_NAME as a module
    add_library(
        ${PROJECT_NAME}
        MODULE ${SOURCES}
    )
    target_link_libraries(
        ${PROJECT_NAME}
        ${SYSREPO_LIBRARIES}
        ${LIBYANG_LIBRARIES}
        ${SRPC_LIBRARIES}
        ${NL_LIBRARIES}
    )
else()
    add_executable(
        ${PROJECT_NAME}
        src/main.c
    )
    target_link_libraries(
        ${PROJECT_NAME}

        # link plugin library with executable
        ${PLUGIN_LIBRARY_NAME}
        ${LIBYANG_LIBRARIES}
        ${SYSREPO_LIBRARIES}
        ${SRPC_LIBRARIES}
        ${NL_LIBRARIES}
    )
endif()

include_directories(
    ${SYSREPO_INCLUDE_DIRS}
    ${LIBYANG_INCLUDE_DIRS}
    ${SRPC_INCLUDE_DIRS}
    ${NL_INCLUDE_DIRS}
)

# augyang support
#if(AUGYANG_FOUND)
#    add_compile_definitions(AUGYANG)
#else(AUGYANG_FOUND)
#    message(WARNING "AUGYANG not found - augeas support will be disabled")
#endif()