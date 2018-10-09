cmake_minimum_required(VERSION 2.8.7)

IF(NOT DEFINED SERVICE_NAME)
    set(SERVICE_NAME com.webos.webosNativeServiceC)
endif(NOT DEFINED SERVICE_NAME)
add_definitions(-DSERVICE_NAME="${SERVICE_NAME}")

project(${SERVICE_NAME} C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC9)
webos_component(1 0 0)

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS})
include_directories(${GLIB2_INCLUDE_DIRS})

pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c)
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS})
include_directories(${PBNJSON_C_INCLUDE_DIRS})

pkg_check_modules(LS2 REQUIRED luna-service2)
webos_add_compiler_flags(ALL ${LS2_CFLAGS})
include_directories(${LS2_INCLUDE_DIRS})

webos_add_compiler_flags(ALL -Wall)

# -- export cmake WEBOS_INSTALL_* variables as C defines
webos_include_install_paths()

set(SOURCE_FILES
    src/main.c
    )

configure_file("files/sysbus/template.manifest.json.in" "${SERVICE_NAME}.manifest.json")
configure_file("files/sysbus/template.app.json.in" "${SERVICE_NAME}.app.json")
configure_file("files/sysbus/template.api.json.in" "${SERVICE_NAME}.api.json")
configure_file("files/sysbus/template.role.json.in" "${SERVICE_NAME}.role.json")
configure_file("files/sysbus/template.service.in" "${SERVICE_NAME}.service")

install (
    FILES "${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME}.manifest.json"
    DESTINATION "${WEBOS_INSTALL_SYSBUS_MANIFESTSDIR}"
)

install (
    FILES "${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME}.app.json"
    DESTINATION "${WEBOS_INSTALL_SYSBUS_PERMISSIONSDIR}"
)

install (
    FILES "${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME}.api.json"
    DESTINATION "${WEBOS_INSTALL_SYSBUS_APIPERMISSIONSDIR}"
)

install (
    FILES "${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME}.role.json"
    DESTINATION "${WEBOS_INSTALL_SYSBUS_ROLESDIR}"
)

install (
    FILES "${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME}.service"
    DESTINATION "${WEBOS_INSTALL_SYSBUS_SERVICESDIR}"
)

install (
    FILES "${CMAKE_CURRENT_BINARY_DIR}/${SERVICE_NAME}.groups.json"
    DESTINATION "${WEBOS_INSTALL_SYSBUS_GROUPSDIR}"
)

add_executable(${SERVICE_NAME} ${SOURCE_FILES})
target_link_libraries(${SERVICE_NAME}
                      ${GLIB2_LDFLAGS}
                      ${PBNJSON_C_LDFLAGS}
                      ${LS2_LDFLAGS}
                      )

webos_build_program()
