{
  "targets": [
    {
      "target_name": "rivide_native",
      "sources": [
        "src/binding.c",
        "src/napi_kem.c",
        "src/napi_dsa.c",
        "src/napi_crypto.c",
        "src/napi_utils.c",
        "deps/src/core/rivide_init.c",
        "deps/src/core/rivide_types.c",
        "deps/src/utils/mem.c",
        "deps/src/utils/random.c",
        "deps/src/crypto/aes_core.c",
        "deps/src/crypto/aes_gcm.c",
        "deps/src/crypto/ghash.c",
        "deps/src/crypto/keccak.c",
        "deps/src/crypto/sha3.c",
        "deps/src/pqc/ntt_simd.c",
        "deps/src/pqc/ml_kem/kem_cbd.c",
        "deps/src/pqc/ml_kem/kem_compress.c",
        "deps/src/pqc/ml_kem/kem_encode.c",
        "deps/src/pqc/ml_kem/kem_ntt.c",
        "deps/src/pqc/ml_kem/kem_poly.c",
        "deps/src/pqc/ml_kem/kem_reduce.c",
        "deps/src/pqc/ml_kem/kem_sampling.c",
        "deps/src/pqc/ml_kem/ml_kem.c",
        "deps/src/pqc/ml_dsa/dsa_ntt.c",
        "deps/src/pqc/ml_dsa/dsa_packing.c",
        "deps/src/pqc/ml_dsa/dsa_poly.c",
        "deps/src/pqc/ml_dsa/dsa_reduce.c",
        "deps/src/pqc/ml_dsa/dsa_rounding.c",
        "deps/src/pqc/ml_dsa/dsa_sampling.c",
        "deps/src/pqc/ml_dsa/ml_dsa.c"
      ],
      "include_dirs": [
        "deps/include",
        "src"
      ],
      "cflags": [
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-O3",
        "-fvisibility=hidden"
      ],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_C_LANGUAGE_STANDARD": "c99",
            "MACOSX_DEPLOYMENT_TARGET": "10.15",
            "OTHER_CFLAGS": [
              "-std=c99",
              "-O3",
              "-D_DARWIN_C_SOURCE"
            ]
          }
        }],
        ["OS=='win'", {
          "defines": [
            "_CRT_SECURE_NO_WARNINGS"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "Optimization": 3
            }
          }
        }]
      ]
    }
  ]
}
