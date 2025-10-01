This is an experimental reference implementation code for [BBB-]DDD-AES ciphers, accompanying the
"Efficient Instances of Docked Double Decker with AES, and Application to Authenticated Encryption" research paper.

Being experimental means that some code parts may be doing things differently than a production-ready code would.
This is done to provide a better illustration of what's possible or to highlight a point.

### Directory structure

* `<cipher type name>`
    * `readability`: reference implementation optimized for readability.
    * `performance`: reference implementation optimized for performance.

### Important configuration options

* Secret zeroization functionality is enabled by default for better out-of-box security, which comes at the performance
  and binary size cost. Adjust as appropriate for your use case in the [main build configuration file](./CMakeLists.txt).
* Various security-enhancing compiler options are also enabled by default, with the same caveat and solution as above.

### Building and development

Our supported target environment is Linux and GCC. There are basic provisions in the code for building it on Windows*
but no official support is provided.

We use the "tagged releases" development model. This means that unless a commit is explicitly tagged as a release, it should
only be used for development. Full list of releases is available here: [releases](https://github.com/intel/ddd-aes/releases).

If you would like to contribute to the project, please review and abide by the [Code of Conduct](./CODE_OF_CONDUCT.md) and
see details in the [Contribution Guide](./CONTRIBUTING.md).

#### To build on Linux (CLI, tested on Fedora 42):

1. Install CMake and GCC
1. `mkdir build`
1. `cd build`
1. `cmake -DCMAKE_BUILD_TYPE=Release ../`
1. `make`

### Citing this work

If you use this software or our paper for your research, please cite us using [`CITATION.bib`](./CITATION.bib).

### Notice

(*) Other names and brands may be claimed as the property of others.
