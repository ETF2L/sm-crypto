# Copyright 2026 ETF2L Contributors, Dave
#
# Static release libraries for the x64 SourceMod extension on Windows, with
# the static C runtime (/MT) SourceMod and its extensions are built with.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_BUILD_TYPE release)
