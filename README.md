# Pangine Disassembler Ground Truth Generator

The LST-based ground truth generation method

This packages includes 3 executables:
 - disasm-gt-extgit: extract assembly and object files from a git managed build directories into separate folders.
 - disasm-gt: generate ground truth using the binary and the assembly files.
 - disasm-gt-check: check the correctness of the ground truth.

The data needs to be given in the format of the output of [disasm-eval-sources](https://github.com/pangine/disasm-eval-sources).

------------------------------
To build the Docker image:

Before this build, you need to build a docker image from *https://github.com/pangine/msvc-wine/tree/2004-ninja* (`git clone --branch 2004-ninja https://github.com/pangine/msvc-wine.git`). Tag the generated image to be **pangine/msvc-wine**

```bash
docker build -t pangine/disasm-gt-generator --build-arg UID=`id -u` .
```

------------------------------
To use the toolkit inside the container:

Assume that you have a compiled projects folder at */path_to_test_cases/x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3*, and the project you want a ground truth is **openssh-7.1p2** (there should be a *bin/openssh-7.1p2* subdirectory inside the compiled projects folder).

The llvm triple for this test case should be **x86_64-pc-linux-gnu-elf**

```bash
OUTPUTDIR="/path_to_test_cases"
TESTCASE="x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3"
LLVMTRIPLE="x86_64-pc-linux-gnu-elf"
PROJECTNAME="openssh-7.1p2"

docker run --rm -it -v ${OUTPUTDIR}:/output \
-e TESTCASE="${TESTCASE}" \
-e LLVMTRIPLE="${LLVMTRIPLE}" \
-e PROJECTNAME="${PROJECTNAME}" \
pangine/disasm-gt-generator /bin/bash -c \
'disasm-gt-extgit -l "${LLVMTRIPLE}" -sd "${PROJECTNAME}" /output/"${TESTCASE}" &&
disasm-gt -l "${LLVMTRIPLE}" -sd "${PROJECTNAME}" /output/"${TESTCASE}" &&
disasm-gt-check -l "${LLVMTRIPLE}" -sd "${PROJECTNAME}" /output/"${TESTCASE}"'
```

You will find the ground truth in the format of sqlite3 at */path_to_test_cases/x86_64-pc-linux-gnu-gcc-7.5.0/%2dO3/gt/openssh-7.1p2/*.

You can choose not to use the **-sd** argument, and the ground truth generator will generate and check ground truth for all the test cases in projects folder.
