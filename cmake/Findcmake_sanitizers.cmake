# TODO
# see https://github.com/arsenm/sanitizers-cmake
# sanitizer_add_blacklist_file("blacklist.txt") # https://github.com/arsenm/sanitizers-cmake#build-targets-with-sanitizer-support

# cmake utils

find_package(cmake_helper_utils REQUIRED)

# \param:TARGET TARGET specify the target to be linked against.
function(add_ubsan_static_link TARGET)
  if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
    target_link_libraries(${TARGET} "-static-libubsan")
  endif(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
endfunction(add_ubsan_static_link)

macro(add_ubsan_definitions TARGET)
  target_compile_definitions(${TARGET} PUBLIC
    UNDEFINED_SANITIZER=1
    UNDEFINED_BEHAVIOR_SANITIZER=1)
  target_compile_options(${TARGET} PUBLIC
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1
    -D_FORTIFY_SOURCE=0
    -DUNDEFINED_SANITIZER=1
    -DUNDEFINED_BEHAVIOR_SANITIZER=1
    -g -O0
    -fPIC
    -fno-optimize-sibling-calls
    -fno-omit-frame-pointer
    -fno-stack-protector
    -fno-wrapv
    -fsanitize=undefined
    -fsanitize=float-divide-by-zero
    -fsanitize=unsigned-integer-overflow
    -fsanitize=implicit-conversion
    -fsanitize=nullability-arg
    -fsanitize=nullability-assign
    -fsanitize=nullability-return
    -fno-sanitize=vptr)
endmacro(add_ubsan_definitions)

macro(add_ubsan_flags)

  # TODO: use target_compile_options
  #target_link_libraries(MyTarget
  #  -fsanitize=...
  #)

  # NOTE: -fsanitize=vptr incompatible with -fno-rtti.
  # https://github.com/google/sanitizers/issues/367
  # As a workaround, you may try building your code with "-fsanitize=undefined -fno-sanitize=vptr"

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -D_FORTIFY_SOURCE=0 \
    -DUNDEFINED_SANITIZER=1 \
    -DUNDEFINED_BEHAVIOR_SANITIZER=1 \
    -g -O0 \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fno-wrapv \
    -fsanitize=undefined \
    -fsanitize=float-divide-by-zero \
    -fsanitize=unsigned-integer-overflow \
    -fsanitize=implicit-conversion \
    -fsanitize=nullability-arg \
    -fsanitize=nullability-assign \
    -fsanitize=nullability-return \
    -fno-sanitize=vptr")

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DUNDEFINED_SANITIZER=1 \
    -DUNDEFINED_BEHAVIOR_SANITIZER=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fno-wrapv \
    -fsanitize=undefined \
    -fsanitize=float-divide-by-zero \
    -fsanitize=unsigned-integer-overflow \
    -fsanitize=implicit-conversion \
    -fsanitize=nullability-arg \
    -fsanitize=nullability-assign \
    -fsanitize=nullability-return \
    -fno-sanitize=vptr")

  set(CMAKE_REQUIRED_FLAGS "${OLD_CMAKE_REQUIRED_FLAGS} \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fno-wrapv \
    -fsanitize=undefined \
    -fsanitize=float-divide-by-zero \
    -fsanitize=unsigned-integer-overflow \
    -fsanitize=implicit-conversion \
    -fsanitize=nullability-arg \
    -fsanitize=nullability-assign \
    -fsanitize=nullability-return \
    -fno-sanitize=vptr")

  # Set linker flags
  set(CMAKE_LINKER_FLAGS
    "${CMAKE_LINKER_FLAGS} \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize=undefined \
    -fsanitize=float-divide-by-zero \
    -fsanitize=unsigned-integer-overflow \
    -fsanitize=implicit-conversion \
    -fsanitize=nullability-arg \
    -fsanitize=nullability-assign \
    -fsanitize=nullability-return \
    -fno-sanitize=vptr")
endmacro(add_ubsan_flags)

# \param:TARGET TARGET specify the target to be linked against.
function(add_asan_static_link TARGET)
  if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
    # see https://github.com/google/sanitizers/wiki/AddressSanitizer#using-addresssanitizer
    target_link_libraries(${TARGET} "-static-libasan")
  endif(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
endfunction(add_asan_static_link)

macro(add_asan_definitions TARGET)
  target_compile_definitions(${TARGET} PUBLIC
    ADDRESS_SANITIZER=1)
  target_compile_options(${TARGET} PUBLIC
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1
    -DADDRESS_SANITIZER=1
    -D_FORTIFY_SOURCE=0
    -g -O0
    -fPIC
    -fno-optimize-sibling-calls
    -fno-omit-frame-pointer
    -fno-stack-protector
    -fsanitize-address-use-after-scope
    -fsanitize=address)
endmacro(add_asan_definitions)

macro(add_asan_flags)
  # TODO: use target_compile_options
  #target_link_libraries(MyTarget
  #  -fsanitize=...
  #)

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DADDRESS_SANITIZER=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-address-use-after-scope \
    -fsanitize=address")

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DADDRESS_SANITIZER=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-address-use-after-scope \
    -fsanitize=address")

  set(CMAKE_REQUIRED_FLAGS "${OLD_CMAKE_REQUIRED_FLAGS} \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-address-use-after-scope \
    -fsanitize=address")

  # Set linker flags
  set(CMAKE_LINKER_FLAGS
    "${CMAKE_LINKER_FLAGS} \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-address-use-after-scope=1 \
    -fsanitize=address")
endmacro(add_ubsan_flags)

# \param:TARGET TARGET specify the target to be linked against.
function(add_tsan_static_link TARGET)
  if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
    target_link_libraries(${TARGET} "-static-libtsan")
  endif(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
endfunction(add_tsan_static_link)

macro(add_tsan_definitions TARGET)
  target_compile_definitions(${TARGET} PUBLIC
    THREAD_SANITIZER=1)
  target_compile_options(${TARGET} PUBLIC
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1
    -DTHREAD_SANITIZER=1
    -DDYNAMIC_ANNOTATIONS_EXTERNAL_IMPL=1
    -D_FORTIFY_SOURCE=0
    -g -O0
    -fPIC
    -fno-optimize-sibling-calls
    -fno-omit-frame-pointer
    -fno-stack-protector
    -fsanitize=thread)
endmacro(add_tsan_definitions)

macro(add_tsan_flags)

  # TODO: use target_compile_options
  #target_link_libraries(MyTarget
  #  -fsanitize=...
  #)

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DTHREAD_SANITIZER=1 \
    -DDYNAMIC_ANNOTATIONS_EXTERNAL_IMPL=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize=thread")

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DTHREAD_SANITIZER=1 \
    -DDYNAMIC_ANNOTATIONS_EXTERNAL_IMPL=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize=thread")

  set(CMAKE_REQUIRED_FLAGS "${OLD_CMAKE_REQUIRED_FLAGS} \
    -fPIC \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize=thread")

  # Set linker flags
  set(CMAKE_LINKER_FLAGS
    "${CMAKE_LINKER_FLAGS} \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize=thread")
endmacro(add_tsan_flags)

# \param:TARGET TARGET specify the target to be linked against.
function(add_msan_static_link TARGET)
  if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
    target_link_libraries(${TARGET} "-static-libmsan")
  endif(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_GNUCC)
endfunction(add_msan_static_link)

macro(add_msan_definitions TARGET)
  target_compile_definitions(${TARGET} PUBLIC
    MEMORY_SANITIZER=1)
  target_compile_options(${TARGET} PUBLIC
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1
    -DMEMORY_SANITIZER=1
    -D_FORTIFY_SOURCE=0
    -g -O0
    -fPIC
    -fPIE
    -fno-elide-constructors
    -fno-optimize-sibling-calls
    -fno-omit-frame-pointer
    -fno-stack-protector
    -fsanitize-memory-track-origins=2
    -fsanitize-memory-use-after-dtor
    -fsanitize=memory)
endmacro(add_msan_definitions)

macro(add_msan_flags)
  # TODO: use target_compile_options
  #target_link_libraries(MyTarget
  #  -fsanitize=...
  #)

  # NOTE: enabled fsanitize-memory-track-origins
  # see https://clang.llvm.org/docs/MemorySanitizer.html#origin-tracking

  # NOTE: -fsanitize-memory-use-after-dtor
  # requires MSAN_OPTIONS=poison_in_dtor=1

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DMEMORY_SANITIZER=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fPIE \
    -fno-elide-constructors \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-memory-track-origins=2 \
    -fsanitize-memory-use-after-dtor \
    -fsanitize=memory")

  # -D_FORTIFY_SOURCE=0 (sanitizer doesn't support source fortification, so disable it to avoid false warnings)
  # Set compiler flags
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -DMEMORY_TOOL_REPLACES_ALLOCATOR=1 \
    -DMEMORY_SANITIZER=1 \
    -D_FORTIFY_SOURCE=0 \
    -g -O0 \
    -fPIC \
    -fPIE \
    -fno-elide-constructors \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-memory-track-origins=2 \
    -fsanitize-memory-use-after-dtor \
    -fsanitize=memory")

  set(CMAKE_REQUIRED_FLAGS "${OLD_CMAKE_REQUIRED_FLAGS} \
    -fPIC \
    -fPIE \
    -fno-elide-constructors \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-memory-track-origins=2 \
    -fsanitize-memory-use-after-dtor \
    -fsanitize=memory")

  # Set linker flags
  set(CMAKE_LINKER_FLAGS
    "${CMAKE_LINKER_FLAGS} \
    -fno-elide-constructors \
    -fno-optimize-sibling-calls \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -fsanitize-memory-track-origins=2 \
    -fsanitize-memory-use-after-dtor \
    -fsanitize=memory")
endmacro(add_msan_flags)

function(check_sanitizer_options)
  # see https://cliutils.gitlab.io/modern-cmake/chapters/basics/functions.html
  set(options
    # skip
  )
  set(oneValueArgs
    ENABLE_UBSAN
    ENABLE_ASAN
    ENABLE_TSAN
    ENABLE_MSAN
    LLVM_SYMBOLIZER_PROGRAM
  )
  set(multiValueArgs
    # skip
  )
  #
  cmake_parse_arguments(
    ARGUMENTS # prefix of output variables
    "${options}" # list of names of the boolean arguments (only defined ones will be true)
    "${oneValueArgs}" # list of names of mono-valued arguments
    "${multiValueArgs}" # list of names of multi-valued arguments (output variables are lists)
    ${ARGN} # arguments of the function to parse, here we take the all original ones
  )
  #
  set(args_unparsed ${ARGUMENTS_UNPARSED_ARGUMENTS})
  if(${ARGUMENTS_VERBOSE})
    message(STATUS "validate: ARGUMENTS_UNPARSED_ARGUMENTS=${ARGUMENTS_UNPARSED_ARGUMENTS}")
  endif(${ARGUMENTS_VERBOSE})

  set(ENABLE_UBSAN ${ARGUMENTS_ENABLE_UBSAN})
  set(ENABLE_ASAN ${ARGUMENTS_ENABLE_ASAN})
  set(ENABLE_TSAN ${ARGUMENTS_ENABLE_TSAN})
  set(ENABLE_MSAN ${ARGUMENTS_ENABLE_MSAN})
  set(LLVM_SYMBOLIZER_PROGRAM ${ARGUMENTS_LLVM_SYMBOLIZER_PROGRAM})

  # Check that the build configuration is not imcompatible.
  if(${ENABLE_UBSAN} AND (${ENABLE_ASAN} OR ${ENABLE_TSAN} OR ${ENABLE_MSAN}))
    # Fail out if we have incompatible configuration.
    message(FATAL_ERROR
      "UndefinedBehaviorSanitizer is not compatible with AddressSanitizer"
      "ThreadSanitizer or MemorySanitizer.")
  endif()

  # Check that the build configuration is not imcompatible.
  if(${ENABLE_ASAN} AND (${ENABLE_MSAN} OR ${ENABLE_TSAN} OR ${ENABLE_UBSAN}))
    # Fail out if we have incompatible configuration.
    message(FATAL_ERROR
      "AddressSanitizer is not compatible with MemorySanitizer"
      "ThreadSanitizer or UndefinedBehaviorSanitizer.")
  endif()

  # Check that the build configuration is not imcompatible.
  if(${ENABLE_MSAN} AND (${ENABLE_ASAN} OR ${ENABLE_TSAN} OR ${ENABLE_UBSAN}))
    # Fail out if we have incompatible configuration.
    message(FATAL_ERROR
      "MemorySanitizer is not compatible with AddressSanitizer"
      "ThreadSanitizer or UndefinedBehaviorSanitizer.")
  endif()

  # Check that the build configuration is not imcompatible.
  if(${ENABLE_TSAN} AND (${ENABLE_ASAN} OR ${ENABLE_MSAN} OR ${ENABLE_UBSAN}))
    # Fail out if we have incompatible configuration.
    message(FATAL_ERROR
      "ThreadSanitizer is not compatible with AddressSanitizer"
      "MemorySanitizer or UndefinedBehaviorSanitizer.")
  endif()

  if(${ENABLE_UBSAN})
    if("$ENV{UBSAN_OPTIONS}" STREQUAL "")
      message(FATAL_ERROR "you must set env. var. with UBSAN_OPTIONS. Example: \
      export UBSAN_OPTIONS=\"fast_unwind_on_malloc=0:handle_segv=0:disable_coredump=0:halt_on_error=1:print_stacktrace=1\" \
      ")
    endif()
  endif(${ENABLE_UBSAN})

  if(${ENABLE_ASAN})
    if("$ENV{ASAN_OPTIONS}" STREQUAL "")
      message(FATAL_ERROR "you must set env. var. with ASAN_OPTIONS. Example: \
      export ASAN_OPTIONS=\"fast_unwind_on_malloc=0:strict_init_order=1:check_initialization_order=true:symbolize=1:handle_segv=0:detect_leaks=1:detect_stack_use_after_return=1:disable_coredump=0:abort_on_error=1\" \
      ")
    endif()
  endif(${ENABLE_ASAN})

  if(${ENABLE_MSAN})
    if("$ENV{MSAN_OPTIONS}" STREQUAL "")
      message(FATAL_ERROR "you must set env. var. with MSAN_OPTIONS. Example: \
      export MSAN_OPTIONS=\"poison_in_dtor=1:fast_unwind_on_malloc=0:check_initialization_order=true:handle_segv=0:detect_leaks=1:detect_stack_use_after_return=1:disable_coredump=0:abort_on_error=1\" \
      ")
    endif()
  endif(${ENABLE_MSAN})

  if(${ENABLE_TSAN})
    if("$ENV{TSAN_OPTIONS}" STREQUAL "")
      message(FATAL_ERROR "you must set env. var. with TSAN_OPTIONS. Example: \
      export TSAN_OPTIONS=\"handle_segv=0:disable_coredump=0:abort_on_error=1:report_thread_leaks=0\" \
      ")
    endif()
  endif(${ENABLE_TSAN})


  if(${ENABLE_UBSAN}
    OR ${ENABLE_ASAN}
    OR ${ENABLE_MSAN}
    OR ${ENABLE_TSAN})
  if(NOT CMAKE_BUILD_TYPE MATCHES "Debug" )
    message(FATAL_ERROR "Sanitizers require Debug build."
      " Current CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
  endif() # NOT CMAKE_BUILD_TYPE MATCHES "Debug"

  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" )
    message(FATAL_ERROR "Sanitizers require Clang"
      " Current CMAKE_CXX_COMPILER_ID=${CMAKE_CXX_COMPILER_ID}")
  endif() # NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang"

  # Sanitizers are implemented in Clang starting 3.1
  # and GCC starting 4.8
  # and supported on Linux x86_64 machines.
  if (NOT UNIX)
    message(FATAL_ERROR "Unsupported operating system."
    " Only Unix systems can use sanitizers.")
  endif (NOT UNIX)

  set(
    ENV{ASAN_SYMBOLIZER_PATH}
    ${LLVM_SYMBOLIZER_PROGRAM}
  )

  message(STATUS
    "ASAN_SYMBOLIZER_PATH=$ENV{ASAN_SYMBOLIZER_PATH}")

  set(
    ENV{MSAN_SYMBOLIZER_PATH}
    ${LLVM_SYMBOLIZER_PROGRAM}
  )

  message(STATUS
    "MSAN_SYMBOLIZER_PATH=$ENV{MSAN_SYMBOLIZER_PATH}")

  set(
    ENV{TSAN_SYMBOLIZER_PATH}
    ${LLVM_SYMBOLIZER_PROGRAM}
  )

  message(STATUS
    "TSAN_SYMBOLIZER_PATH=$ENV{TSAN_SYMBOLIZER_PATH}")

  set(
    ENV{UBSAN_SYMBOLIZER_PATH}
    ${LLVM_SYMBOLIZER_PROGRAM}
  )

  message(STATUS
    "UBSAN_SYMBOLIZER_PATH=$ENV{UBSAN_SYMBOLIZER_PATH}")
  endif()
endfunction(check_sanitizer_options)
