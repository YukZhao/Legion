# Legion

Source code for **"Ensemble Fuzzing with Dynamic Resource Scheduling and Multidimensional Seed Evaluation"**.

## Build Legion

```bash
make -C src/instrumentor
make -C src/legion
```

## Run Legion

Set the script path first:

```bash
export LEGION_SCRIPT_DIR=$PWD/scripts
```

Run Legion with a target archive and seed directory:

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
