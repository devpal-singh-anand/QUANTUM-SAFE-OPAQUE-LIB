{
  "targets": [
    {
      "target_name": "qh_opaque",
      "sources": [
        "native/src/qh_opaque.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "native/libOTe/install/include",
        "native/leap"
      ],
      "libraries": [
        "-L<(module_root_dir)/native/libOTe/install/lib",
        "-lOTe",
        "-lboost_system",
        "-lboost_thread",
        "-lpthread"
      ],
      "cflags_cc": [
        "-std=c++17",
        "-march=core-avx2",
        "-maes",
        "-mrdseed",
        "-O2",
        "-fexceptions"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS=0"
      ]
    }
  ]
}