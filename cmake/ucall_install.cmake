# The install rules, the export set, the CMake and pkg-config package files, and the preview SDK archive.

# `find_package(ucall)` names the libraries `ucall::static` and, when built, `ucall::shared`. The `sdk` component holds
# both, the `ucall` command-line client, the C headers, both package files and the license.
if (UCALL_INSTALL)
    include(CMakePackageConfigHelpers)
    set(ucall_config_install_dir_ "${CMAKE_INSTALL_LIBDIR}/cmake/ucall")
    install(
        TARGETS ucall_header ucall_static
        EXPORT ucallTargets
        COMPONENT sdk
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
    # The archive's consumers link the liburing it was built with, installed beside it as `ucall::uring`.
    if (TARGET uring)
        install(
            TARGETS uring
            EXPORT ucallTargets
            COMPONENT sdk
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
    endif ()
    if (UCALL_BUILD_SHARED)
        install(
            TARGETS ucall_shared
            EXPORT ucallTargets
            COMPONENT sdk
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
    endif ()
    install(
        TARGETS ucall_cli
        COMPONENT sdk
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    install(
        EXPORT ucallTargets
        NAMESPACE ucall::
        DESTINATION ${ucall_config_install_dir_}
        COMPONENT sdk
    )
    configure_package_config_file(
        "${PROJECT_SOURCE_DIR}/cmake/ucallConfig.cmake.in" "${PROJECT_BINARY_DIR}/ucallConfig.cmake"
        INSTALL_DESTINATION ${ucall_config_install_dir_}
    )
    write_basic_package_version_file(
        "${PROJECT_BINARY_DIR}/ucallConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(
        FILES "${PROJECT_BINARY_DIR}/ucallConfig.cmake" "${PROJECT_BINARY_DIR}/ucallConfigVersion.cmake"
        DESTINATION ${ucall_config_install_dir_}
        COMPONENT sdk
    )
    install(
        DIRECTORY c/ucall
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        COMPONENT sdk
    )
    install(
        FILES LICENSE
        DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ucall
        COMPONENT sdk
    )

    # A `.pc` naming the shared library, for the consumers CMake never reaches. Spelling the prefix against
    # `${pcfiledir}` keeps it correct after the tree moves, and only a relative `GNUInstallDirs` path may follow it.
    if (UCALL_BUILD_SHARED)
        file(RELATIVE_PATH ucall_pc_relative_prefix_ "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig" "${CMAKE_INSTALL_PREFIX}")
        set(ucall_pc_prefix_ "\${pcfiledir}/${ucall_pc_relative_prefix_}")
        if (IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
            set(ucall_pc_libdir_ "${CMAKE_INSTALL_LIBDIR}")
        else ()
            set(ucall_pc_libdir_ "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
        endif ()
        if (IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
            set(ucall_pc_includedir_ "${CMAKE_INSTALL_INCLUDEDIR}")
        else ()
            set(ucall_pc_includedir_ "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
        endif ()
        configure_file(cmake/ucall.pc.in "${PROJECT_BINARY_DIR}/ucall.pc" @ONLY)
        install(
            FILES "${PROJECT_BINARY_DIR}/ucall.pc"
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
            COMPONENT sdk
        )
    endif ()

    # `cpack --config <build>/CPackConfig.cmake` packs the `sdk` component alone, stripped.
    set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
    if (WIN32)
        set(CPACK_GENERATOR ZIP)
    else ()
        set(CPACK_GENERATOR TGZ)
    endif ()
    set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
    set(CPACK_COMPONENTS_ALL sdk)
    set(CPACK_STRIP_FILES ON)
    include(CPack)
endif ()
