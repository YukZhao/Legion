# Legion

Source code for **"Ensemble Fuzzing with Dynamic Resource Scheduling and Multidimensional Seed Evaluation"**.

## Build Legion

```bash
make -C src/instrumentor
make -C src/legion
```

Or build with Docker:

```bash
docker build -t legion .
```

## Build Target and Run Legion

Set the script path first:

```bash
export LEGION_SCRIPT_DIR=$PWD/scripts
```

Use `--build` to build the target binaries first, then `--run` to start fuzzing:

```bash
./src/legion/legion \
  --build --run \
  -zip /path/to/target.zip \
  --initial /path/to/seeds \
  --resource 6 \
  --round 72 \
  --round-time 600 \
  --afl --aflfast --fairfuzz --libfuzzer --radamsa --qsym \
  > legion.log 2>&1
```

- `/path/to/target.zip` is the target program package. It should contain a `fuzzbuild` script that builds an executable named `app`.
- `/path/to/seeds` is the initial seed corpus directory.

```bash
docker run --rm -it \
  -v /path/to/target.zip:/target.zip \
  -v /path/to/seeds:/seeds \
  legion \
  legion --build --run -zip /target.zip --initial /seeds \
    --resource 6 --round 72 --round-time 600 \
    --afl --aflfast --fairfuzz --libfuzzer --radamsa --qsym \
  > legion.log 2>&1
```
