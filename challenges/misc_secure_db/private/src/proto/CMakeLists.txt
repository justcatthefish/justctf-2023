add_library(secure_db_task-proto)

## Protobuf & GRPC
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
include(cmake/GRPC_Util.cmake)

grpc_generate_cpp(GRPC_SRCS GRPC_HDRS oracle.proto)
grpc_generate_python(GRPC_PY oracle.proto)

add_custom_target(secure_db_task-proto-generate DEPENDS ${GRPC_SRC} ${GRPC_HEADER} ${GRPC_PY})
add_dependencies(secure_db_task-proto secure_db_task-proto-generate)

target_sources(secure_db_task-proto
        PRIVATE
        ${GRPC_SRCS}
        ${GRPC_HDRS}
)

add_custom_command(TARGET secure_db_task-proto POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/proto/*py ${CMAKE_SOURCE_DIR}/frontend/generated
        && sed -i -E 's/^import.*_pb2/from . \\0/' ${CMAKE_SOURCE_DIR}/frontend/generated/*.py
)

target_include_directories(
        secure_db_task-proto
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}
)

target_link_libraries(secure_db_task-proto
        PUBLIC
        gRPC::grpc++
        ${PROTOBUF_LIBRARIES}
)