# Supporting inputs

Everything the notebooks read besides the dataset itself. Paths inside the frozen records keep the layout of the acquisition
project (`Dataset/…`, `Manifests/…`, `Native/…`); the notebooks map them onto this folder with a small `relocate` helper so
that every recorded SHA-256 digest still verifies.

| Folder | Content |
|---|---|
| `configs/` | development design, feature definition, native campaign plans, model search and calibration settings, the frozen SCAR-MLKEM design |
| `manifests/` | derived-file digests of notebooks 01–04, the hash bindings that guard the archived baseline and modern campaigns, build logs and native self-test logs, the calibration source freeze, and the plan, registration and worker script of every Raspberry Pi campaign (development, confirmation, replication, 1.5 GHz, interference, real-time) |
| `native/` | C sources, headers and build scripts of the baseline and modern cache harnesses with their frozen snapshots, and the SCAR-MLKEM harness (`Development/core_controller`) with the vectorised public-matrix library (`Development/vector_public_matrix`) |
| `models/` | fitted logistic, random-forest and gradient-boosting predictors with their out-of-fold and development predictions |
| `binaries/` | the aarch64 executable of the modern-policy harness that produced the archived campaign |
| `calibration/` | the eight-process cost calibration behind the frozen operation costs |
