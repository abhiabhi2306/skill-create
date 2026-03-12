---
name: model-file-vuln-scan
description: >
  Scan repositories for AI/ML model file vulnerabilities including arbitrary code execution
  via pickle deserialization, Keras Lambda layer backdoors, GGUF heap overflows, ONNX custom
  operator abuse, SafeTensors header manipulation, trust_remote_code ACE, MLflow pyfunc ACE,
  TensorRT engine deserialization, PMML/OpenVINO XXE, Keras from_config class injection,
  ONNX external data path traversal, LoRA adapter manipulation, tokenizer config injection,
  HuggingFace snapshot symlink attacks, TOCTOU race conditions, and scanner bypass techniques.
  Use this skill when the user asks to scan a repository for model file security issues,
  audit model loading code, check for malicious model files, find vulnerabilities in AI
  model formats (.pkl, .pt, .pth, .h5, .keras, .gguf, .safetensors, .onnx, .joblib, .npy,
  .npz, .mlmodel, .mlpackage, .engine, .plan, .pmml, .pdparams, .pdmodel, .caffemodel,
  config.pbtxt, tokenizer.json, adapter_model.safetensors), or assess model supply chain
  risks. Trigger also for: "model ACE", "torch.load vuln", "pickle deserialization in ML",
  "GGUF parsing bug", "malicious model file", "model backdoor", "trust_remote_code",
  "MLflow model", "TensorRT deserialization", "PMML XXE", "LoRA poisoning".
---

# Model File Vulnerability Scanner

You are performing a security audit of a repository for AI/ML model file vulnerabilities.
Your goal is to find **confirmed, exploitable vulnerabilities** in how model files are created,
loaded, and used — with special emphasis on arbitrary code execution, backdoors, memory
corruption, and scanner bypass techniques.

This skill targets all vulnerability classes across model file formats: .safetensors, .gguf,
.keras, .h5, .joblib, .pkl, .pt, .pth, .onnx, .npy, .npz, .pb, .tflite, .mlmodel,
.mlpackage, .engine, .plan, .pmml, .pdparams, .pdmodel, .caffemodel, config.pbtxt,
tokenizer.json, adapter_model.safetensors, SavedModel dirs, MLflow model artifacts,
Ray/DeepSpeed checkpoints, and Triton model repositories.

## Mandatory Gates

**[GATE-1: VERIFY-BEFORE-REPORT]** Every finding MUST be verified against actual code or file
content before being reported. Do not report based on pattern matching alone. Trace the
complete data flow or attack path. If you cannot verify, discard the finding.

**[GATE-2: NO-THEORETICAL]** Only report exploitable vulnerabilities. A function being
"dangerous" is not a finding. There must be a realistic attack path: attacker-controlled
input → dangerous operation → exploitable outcome.

**[GATE-3: STRICT-SEQUENCE]** Follow phases in order. Build the inventory in Phase 0 before
searching in Phase 1. Verify before reporting in Phase 4. Do not skip phases.

**[GATE-4: VERBATIM-CODE]** Every finding must contain the exact vulnerable lines copied
verbatim from the source. No paraphrasing. Include file path and line numbers.

**[GATE-5: FULL-COVERAGE]** Analyze every model-loading code path and every model file
reference. No sampling. Every entry point that loads a model file must be evaluated.

**[GATE-6: POC-OR-DISCARD]** For Critical and High findings, a proof-of-concept or concrete
exploit payload must be constructable from the analysis. If a PoC cannot be constructed,
the finding must be downgraded or discarded.

---

## Audit Methodology

### Phase 0: Inventory

Build ground-truth inventory before any analysis:

1. **Locate all model files** — find .pkl, .pt, .pth, .h5, .keras, .gguf, .safetensors,
   .onnx, .joblib, .npy, .npz, .pb, .tflite, .mlmodel, .mlpackage, .engine, .plan,
   .pmml, .pdparams, .pdmodel, .caffemodel, tokenizer.json, adapter_model.safetensors,
   config.json (HuggingFace model configs), SavedModel dirs, MLmodel files (MLflow),
   config.pbtxt (Triton), checkpoint files (Ray, DeepSpeed)
2. **Locate all model-loading code** — find torch.load, pickle.load, keras.load_model,
   tf.saved_model.load, ggml_init, safetensors.load, joblib.load, np.load, onnxruntime,
   mlflow.pyfunc.load_model, AutoModel.from_pretrained, trust_remote_code=True,
   trt.Runtime.deserialize_cuda_engine, paddle.load, coremltools.models.MLModel,
   ray.tune.Checkpoint.from_directory, snapshot_download
3. **Identify entry points** — API endpoints, CLI commands, scripts that accept model paths
   from users (file uploads, HuggingFace Hub downloads, user-provided paths, MLflow runs)
4. **Map trust boundaries** — where do model files come from? Downloaded from internet?
   Uploaded by users? Internal artifact store? Is trust_remote_code ever True? Untrusted = priority.
5. **Record dependencies** — torch, tensorflow, keras, safetensors, ggml, onnxruntime,
   joblib, numpy, mlflow, transformers, paddlepaddle, coremltools, tensorrt versions used
6. **Identify HuggingFace integration depth** — does the codebase use from_pretrained,
   snapshot_download, hf_hub_download? What repos does it pull from? Is revision pinned?

Record the inventory. It is the source of truth for GATE-5.

### Phase 1: Code Analysis — Dangerous Model Loading Patterns

Search the codebase for dangerous model loading patterns. For each match, trace the
full data flow to determine if it is exploitable.

**Use these search patterns:**

```
# Pickle-based deserialization (ACE)
Grep: "torch\.load\s*\(|pickle\.load\s*\(|pickle\.loads\s*\("
Grep: "joblib\.load\s*\(|load_model\s*\(|tf\.keras\.models\.load_model"
Grep: "np\.load\s*\(.*allow_pickle.*True|numpy\.load\s*\(.*allow_pickle"
Grep: "dill\.load|cloudpickle\.load|marshal\.load"

# Keras Lambda / custom layers (ACE on inference)
Grep: "Lambda\s*\(|custom_objects|get_custom_objects|from_config"
Grep: "tf\.keras\.utils\.get_registered_object|keras_serialization"
Grep: "model\.compile.*run_eagerly|tf\.function.*experimental_compile"

# GGUF / GGML parsing
Grep: "gguf_init_from_file|ggml_init|llama_load_model|gguf_get_val"
Grep: "n_kv\s*\*|header\.n_kv|kv_count\s*\*|malloc.*header\."

# ONNX custom operators
Grep: "onnxruntime\.InferenceSession|ort\.InferenceSession"
Grep: "register_custom_op|CustomOp|OrtCustomOp|add_custom_op"
Grep: "onnx\.load\s*\(|onnx_model\.graph|NodeProto"

# SafeTensors (generally safer but check metadata handling)
Grep: "safe_open\s*\(|safetensors\.load\s*\(|from_file\s*\("
Grep: "metadata\[|\.metadata\(\)|header_size\s*\*|tensor_count\s*\*"

# Model path injection (user controls model file path)
Grep: "request\..*model|args\.model|params\[.*model|user.*model.*path"
Grep: "huggingface_hub\.hf_hub_download|from_pretrained\s*\(|snapshot_download"
Grep: "os\.path\.join.*model|open\s*\(.*model_path|load.*user.*provided"

# Unsafe deserialization in config/weights
Grep: "yaml\.load\s*\(|eval\s*\(.*config|exec\s*\(.*layer"
Grep: "json\.loads.*__class__|object_hook.*__reduce__"

# TensorFlow SavedModel
Grep: "tf\.saved_model\.load|hub\.load\s*\(|tf\.keras\.models\.load"
Grep: "concrete_function|tf\.function.*python_function"

# Arbitrary code in model metadata
Grep: "metadata.*eval|metadata.*exec|model_card.*exec"

# HuggingFace trust_remote_code (CRITICAL — executes Python files from Hub)
Grep: "trust_remote_code\s*=\s*True|trust_remote_code=True"
Grep: "from_pretrained\s*\(|AutoModel\.from_pretrained|AutoTokenizer\.from_pretrained"
Grep: "snapshot_download\s*\(|hf_hub_download\s*\(|huggingface_hub\."
Grep: "revision\s*=.*request|revision\s*=.*user|revision\s*=.*args\."

# Keras / HuggingFace from_config() arbitrary class instantiation
Grep: "from_config\s*\(|\.from_config\s*\(|get_registered_object"
Grep: "class_name.*deserialize|deserialize.*class_name"

# MLflow model loading (ACE via pyfunc)
Grep: "mlflow\.pyfunc\.load_model|mlflow\.models\.load_model"
Grep: "mlflow\.pytorch\.load_model|mlflow\.sklearn\.load_model"
Grep: "mlflow\.artifacts\.download_artifacts|mlflow\.tracking"

# Ray / DeepSpeed checkpoint deserialization
Grep: "ray\.tune\.Checkpoint|ray\.train\.Checkpoint|torch\.load.*checkpoint"
Grep: "deepspeed\.load_checkpoint|deepspeed_checkpoint|zero_to_fp32"
Grep: "cloudpickle\.load|ray\.cloudpickle"

# TensorRT engine deserialization (binary, memory corruption risk)
Grep: "trt\.Runtime\(\)|tensorrt\.Runtime|deserialize_cuda_engine"
Grep: "engine\.serialize\|load_engine\|build_engine"

# PMML / OpenVINO XML (XXE risk)
Grep: "pmml|PMML|pypmml|sklearn2pmml|jpmml"
Grep: "openvino\.runtime|ov\.Core\(\)|core\.read_model|IECore"
Grep: "xml\.etree\.ElementTree|lxml\.etree|minidom.*parse"

# PaddlePaddle deserialization
Grep: "paddle\.load\s*\(|paddle\.static\.load|fluid\.io\.load"
Grep: "paddlepaddle|paddle\.jit\.load"

# CoreML custom layers (.mlmodel, .mlpackage)
Grep: "coremltools\.|ct\.models\.MLModel|MLModel\s*\("
Grep: "CustomLayer|NeuralNetworkCustomLayer|custom_layer"

# NCNN / Caffe custom ops
Grep: "ncnn\.|Net\.load_param|Net\.load_model"
Grep: "caffe\.|caffe\.Net|net\.copy_from|caffe_pb2"

# ONNX external data path traversal
Grep: "data_location|load_external_data|external_data_helper"
Grep: "onnx\.load\s*\(.*load_external_data|TensorProto.*data_location"

# HuggingFace model card YAML front matter
Grep: "yaml\.load\s*\(|yaml\.unsafe_load|model_card|README\.md.*yaml"
Glob: "**/README.md"  # Check for yaml.load usage on model card files

# Tokenizer config injection (native Rust code via HF tokenizers library)
Grep: "tokenizer\.json|PreTrainedTokenizerFast|AutoTokenizer"
Grep: "normalizer.*type.*Custom|pre_tokenizer.*Custom|post_processor.*Custom"
Grep: "added_tokens_decoder|special_tokens_map"

# Triton Python backend (arbitrary Python execution)
Grep: "triton.*model_repository|tritonclient|triton_python_backend"
Grep: "config\.pbtxt|backend.*python|TritonPythonModel"

# LoRA / adapter weight manipulation
Grep: "peft\.|load_adapter|adapter_model|lora_weights"
Grep: "PeftModel\.from_pretrained|set_adapter|merge_adapter"

# Spark MLlib Java deserialization
Grep: "pyspark\.ml\.Pipeline|MLReader\.load|PipelineModel\.load"
Grep: "sc\.parallelize.*model|SparkContext.*model"

# TOCTOU race condition in model validation
Grep: "os\.path\.exists.*model.*load|scan.*model.*load\s*\("
Grep: "validate.*model.*path.*torch\.load|check.*file.*open\s*\("
```

For each match, determine:
- Is the model path/file attacker-controlled?
- Does the loader support pickle or arbitrary code execution?
- Is there input validation / allowlisting of model sources?
- Does the code use `weights_only=True` (PyTorch) or equivalent safe loading?

### Phase 2: Model File Format Deep Analysis

For each model format found or loaded in the codebase, apply format-specific analysis.
Read `references/vulnerability-classes.md` for the complete checklist per format.

**Priority order:**
1. **trust_remote_code=True** — CRITICAL: executes arbitrary Python files from HuggingFace Hub
2. **Pickle-based formats** (.pkl, .pt, .pth via torch.load) — highest single-file ACE risk
3. **Keras HDF5** (.h5, .keras) — Lambda layer ACE on inference
4. **MLflow pyfunc** — executes arbitrary Python on model.predict()
5. **GGUF** (.gguf) — heap overflow / integer overflow in parser
6. **ONNX** (.onnx) — custom operator ACE, control flow abuse, external data traversal
7. **TensorRT** (.engine, .plan) — binary engine deserialization, memory corruption
8. **SafeTensors** (.safetensors) — metadata injection, header manipulation
9. **Joblib** (.joblib) — pickle-based ACE
10. **NumPy** (.npy, .npz) — allow_pickle ACE
11. **TensorFlow SavedModel** — tf.function deserialization, custom layer ACE
12. **TFLite** (.tflite) — flatbuffer parsing, custom op abuse
13. **PaddlePaddle** (.pdparams, .pdmodel) — pickle-based parameter serialization
14. **CoreML** (.mlmodel, .mlpackage) — custom layer native code execution
15. **PMML** (.pmml) — XML External Entity (XXE) injection
16. **OpenVINO IR** (.xml + .bin) — XML XXE injection
17. **Caffe** (.caffemodel + .prototxt) — custom layer ACE
18. **Ray/DeepSpeed checkpoints** — cloudpickle/pickle checkpoint deserialization
19. **LoRA/adapters** (adapter_model.safetensors, adapter_config.json) — output manipulation
20. **Tokenizer configs** (tokenizer.json) — native Rust custom normalizer code execution
21. **HuggingFace snapshots** — symlink following during snapshot_download
22. **Triton Python backends** (config.pbtxt + model.py) — arbitrary Python execution
23. **Spark MLlib** — Java ObjectInputStream deserialization

**For each format present, analyze:**
- Are files loaded from untrusted sources (user uploads, hub downloads, user-specified paths)?
- Does the loading code use unsafe options (no `weights_only=True`, `allow_pickle=True`)?
- Are there custom layer/operator registrations that execute code?
- Is there header/metadata validation before allocation?
- Does the codebase modify or re-serve model files (re-export risk)?

### Phase 3: Scanner Bypass & Backdoor Analysis

Analyze whether the codebase's model scanning/validation can be bypassed and whether
backdoors could persist undetected.

**Scanner bypass patterns to look for:**
- Magic byte validation without full format verification
- Metadata-only scanning that misses embedded pickle data in tensor metadata
- Allowlist-based format checks that can be confused by polyglot files
- Async loading patterns that load headers first, payload later (TOCTOU)
- Compression wrappers (zip-within-zip, nested archives) that scanners don't traverse
- Scanners that check file extension but don't verify actual format magic bytes
- trust_remote_code flows that are never scanned (code is downloaded at runtime, not pre-scanned)
- LoRA adapters that are loaded without scanning (only base model is scanned)

**Backdoor persistence patterns:**
- Model weights that produce different outputs for specific trigger inputs
- Lambda layers or custom ops that activate conditionally (inference-time backdoors)
- Metadata fields that store executable code executed at load time
- SavedModel signatures with embedded Python code
- ONNX If/Loop nodes with hidden branches
- LoRA adapter weights that steer the base model toward attacker-chosen outputs on trigger
- GGUF metadata strings injected into prompts or SQL queries by the consuming app

**Questions to answer:**
- Does the repo have a model scanner? What does it check?
- Can the scanner be bypassed by embedding pickle in an otherwise-valid safetensors file?
- Are custom layers deserialized before or after safety checks?
- Is trust_remote_code=True used, bypassing all file-based scanning entirely?
- Are LoRA/adapter files scanned separately from base models?
- Is there a way to make malicious code execute only on specific inputs (evading test scanners)?

### Phase 3b: HuggingFace Ecosystem Deep Analysis

The HuggingFace ecosystem introduces a distinct class of vulnerabilities beyond individual
file formats. Analyze these specifically when the codebase uses `transformers`, `huggingface_hub`,
`peft`, or `diffusers`.

**trust_remote_code analysis:**
1. Search for all `trust_remote_code=True` occurrences
2. For each: trace where the `repo_id` or model name comes from — is it hardcoded or user-supplied?
3. Even hardcoded repos are a risk if the upstream repo is compromised or can be poisoned
4. Check if the `revision` parameter is pinned to a specific commit hash (not a branch name)
5. A branch name like `main` can be updated by the repo owner at any time — unpinned = supply chain risk

**snapshot_download / hf_hub_download analysis:**
1. Check if `local_dir_use_symlinks=True` (default) — symlinks in the downloaded repo can
   point outside the local directory (symlink following vulnerability)
2. Check if downloaded files are extracted with `shutil.unpack_archive` — path traversal risk
3. Check if `revision` is pinned or user-controlled

**from_config() analysis:**
1. Find all `from_config(config_dict)` calls
2. Trace where `config_dict` originates — if it comes from a user-uploaded JSON or
   a remotely downloaded config.json, it can specify arbitrary class names
3. Keras `from_config` will instantiate any registered class by name; HuggingFace
   `AutoConfig.from_pretrained` + `AutoModel.from_config` may auto-import custom classes

### Phase 4: Verification (5-Point Sanity Check)

For every candidate finding from Phases 1-3, apply the full verification checklist.
**A finding that fails any check is discarded.**

1. **File existence** — does the file actually exist at the claimed path?
2. **Verbatim match** — do the code lines match exactly? Open the file and re-read the lines.
3. **Exploitability path** — is there a realistic code path from an attacker-controlled input
   to the dangerous operation? Trace every step. No assumed links.
4. **Reachability** — is the vulnerable function actually called in production? Not just tests?
5. **No compensating control** — is there a safety check, allowlist, or sandbox that would
   prevent exploitation? If yes, can it be bypassed?

**Additional model-specific verification:**
- For pickle findings: verify `weights_only=False` (default) or explicit `pickle.load` is used
- For Keras Lambda: verify the model format supports Lambda layers AND custom code
- For GGUF: verify the malloc call uses an attacker-controlled count without bounds check
- For ONNX custom ops: verify the custom op is registered and executes native code
- For path injection: verify the user-controlled string reaches an actual file load call

**PoC construction (required for Critical/High):**
Attempt to construct a minimal PoC showing the attack:
- For ACE: write the minimal malicious model creation code
- For heap overflow: specify exact header fields to set and their values
- For backdoor: describe the trigger condition and expected hidden behavior
- For path injection: show the exact request that loads an attacker-specified file

If the PoC cannot be constructed after 3 attempts, downgrade severity or discard.

### Phase 4b: Ruling — Hard-Stop Discard

Auto-discard any finding where ALL of the following apply:
- The vulnerability only exists in test files, fixtures, or examples
- Requires the attacker to have already compromised the system
- Requires victim to run an attacker-provided script (not just load an attacker's model file)
- Is a missing best-practice with no concrete attack path
- Is a DoS via malformed file (unless explicitly in scope as Medium)

### Phase 5: Report Generation

Generate `report.html` (or user-specified filename) using the template in
`references/report-template.md`. Save to the current working directory.

Each finding must include:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Vulnerability class** with CWE ID and CVSS 3.1 score
- **Affected file** with line numbers and GitHub permalink (if GitHub repo)
- **Vulnerable code snippet** — verbatim, not paraphrased
- **Attack scenario** — who is the attacker, what do they control, what happens
- **Steps to reproduce** — numbered, concrete, reproducible
- **Proof of Concept** — minimal model creation code + load trigger code
- **HuggingFace PoC guidance** — how to create and host the malicious model on HuggingFace
  for a full end-to-end PoC demonstration (if applicable)
- **Impact** — concrete outcome (RCE, data exfil, silent output manipulation, etc.)
- **Mitigation** — specific actionable fix with code example

---

## Vulnerability Classes — Quick Reference

For full patterns, see `references/vulnerability-classes.md`.

### CLASS-1: Pickle Deserialization ACE (CRITICAL)
**Formats:** .pkl, .pt, .pth, .joblib, any format using pickle internally
**Trigger:** `torch.load()` without `weights_only=True`, `pickle.load()`, `joblib.load()`
**Condition:** Attacker can supply a model file (upload, hub download, user-specified path)
**Mechanism:** `__reduce__` method in pickled object executes arbitrary OS commands on load
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8 (High, UI:N possible = 9.8 Critical)

### CLASS-2: Keras Lambda Layer ACE (CRITICAL)
**Formats:** .h5, .keras (HDF5-based Keras models)
**Trigger:** `tf.keras.models.load_model()`, `keras.models.load_model()`
**Condition:** Attacker can supply a Keras model file
**Mechanism:** Lambda layers contain arbitrary Python code executed during inference
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-3: GGUF Header Parsing Heap Overflow (CRITICAL)
**Formats:** .gguf
**Trigger:** GGUF loader (llama.cpp, ggml, any library parsing GGUF format)
**Condition:** Attacker supplies a crafted .gguf file with manipulated n_kv or tensor count
**Mechanism:** Unchecked header field used in malloc/loop → heap overflow → potential RCE
**Pattern:** `malloc(header.n_kv * sizeof(...))` without bounds checking
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.5+

### CLASS-4: ONNX Custom Operator ACE (HIGH)
**Formats:** .onnx
**Trigger:** `onnxruntime.InferenceSession()` with models using custom ops
**Condition:** Attacker supplies ONNX model with registered malicious custom op
**Mechanism:** Custom operator implementation (native C++ or Python) runs arbitrary code
**CVSS:** AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H = 8.0

### CLASS-5: NumPy allow_pickle ACE (HIGH)
**Formats:** .npy, .npz
**Trigger:** `np.load(file, allow_pickle=True)`
**Condition:** Attacker controls the .npy/.npz file path or content
**Mechanism:** Pickle objects embedded in numpy arrays execute on load
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-6: TensorFlow SavedModel Custom Layer ACE (HIGH)
**Formats:** SavedModel directories, .pb
**Trigger:** `tf.saved_model.load()`, `hub.load()`
**Condition:** Attacker supplies a SavedModel with malicious custom layers
**Mechanism:** Custom layer `call` method or `from_config` executes arbitrary Python
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-7: Model Path Injection (HIGH)
**Formats:** Any
**Trigger:** User-controlled string reaches `torch.load(user_path)` or equivalent
**Condition:** Web/API endpoint accepts model file paths without validation
**Mechanism:** Path traversal to load arbitrary files; or SSRF to load remote model files
**CVSS:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8

### CLASS-8: SafeTensors Header Integer Overflow (MEDIUM)
**Formats:** .safetensors
**Trigger:** SafeTensors parser with crafted header_size field
**Condition:** Attacker supplies crafted .safetensors file
**Mechanism:** Integer overflow in header_size computation → heap allocation too small →
heap overflow during tensor data copy
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H = 5.6

### CLASS-9: Inference-Time Backdoor (MEDIUM)
**Formats:** .h5, .keras, .onnx, SavedModel
**Trigger:** Model is used for inference on specific trigger inputs
**Condition:** Attacker controls model file; victim loads and uses for inference
**Mechanism:** Conditional logic (Lambda layers, custom ops, ONNX If nodes) activates on
specific inputs to produce manipulated outputs or execute code silently
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N = 5.9

### CLASS-10: Zip/Tar Directory Traversal in Model Archives (MEDIUM)
**Formats:** .pt (ZIP-based), .keras (ZIP-based in newer versions), .npz (ZIP)
**Trigger:** Extracting or loading a crafted ZIP/TAR-based model file
**Condition:** Attacker supplies crafted archive
**Mechanism:** Archive entry path contains `../` sequences → write outside target dir
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N = 6.5

### CLASS-11: Scanner Bypass (HIGH — if confirmed)
**Formats:** Any
**Trigger:** Security scanner validates format, misses embedded malicious payload
**Condition:** Attacker crafts polyglot/hybrid file that passes scanner but executes on load
**Mechanism:** Valid safetensors header + embedded pickle data in metadata; or magic byte
spoofing; or payload in tensor data region decoded and eval'd by custom op
**CVSS:** Varies — typically inherits severity of the bypassed vulnerability class

### CLASS-12: HuggingFace trust_remote_code ACE (CRITICAL)
**Formats:** HuggingFace model repos (any format — code is downloaded separately)
**Trigger:** `AutoModel.from_pretrained(repo, trust_remote_code=True)` or any `from_pretrained`
**Condition:** Attacker controls or compromises the HuggingFace repo being loaded
**Mechanism:** HuggingFace downloads `modeling_*.py`, `configuration_*.py`, `tokenization_*.py`
from the repo and executes them. Arbitrary Python in those files runs on the victim's machine.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8 (supply chain: 9.8 if repo name typosquatted)

### CLASS-13: MLflow pyfunc Arbitrary Code Execution (CRITICAL)
**Formats:** MLflow model artifacts (MLmodel file + any flavor)
**Trigger:** `mlflow.pyfunc.load_model(model_uri)` followed by `model.predict(data)`
**Condition:** Attacker can supply or modify the MLflow model artifact
**Mechanism:** MLflow's `python_function` flavor stores a Python module that runs arbitrary
code in its `predict()` method. No sandboxing is applied.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-14: Keras from_config() Arbitrary Class Instantiation (HIGH)
**Formats:** .h5, .keras, config.json (HuggingFace Keras models)
**Trigger:** `tf.keras.layers.deserialize(config)`, `model.from_config(config_dict)`
**Condition:** Attacker controls the config JSON specifying layer class names
**Mechanism:** Keras deserializes layers by looking up `class_name` in registered objects.
An attacker who can supply a config can instantiate any registered class with arbitrary
constructor arguments, potentially triggering unexpected initialization code.
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.5

### CLASS-15: ONNX External Data Path Traversal (HIGH)
**Formats:** .onnx + external data files
**Trigger:** `onnx.load(model_path, load_external_data=True)`
**Condition:** Attacker supplies a crafted .onnx file with manipulated `data_location` paths
**Mechanism:** ONNX TensorProto's `data_location` field references external data files by path.
A path like `../../etc/shadow` causes the loader to read arbitrary files from the filesystem.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N = 6.5

### CLASS-16: TensorRT Engine Deserialization Memory Corruption (HIGH)
**Formats:** .engine, .plan (TensorRT serialized engines)
**Trigger:** `trt.Runtime().deserialize_cuda_engine(engine_data)`
**Condition:** Attacker supplies a crafted TensorRT engine file
**Mechanism:** TensorRT engine files are opaque binary blobs parsed by NVIDIA's runtime.
Malformed engines can trigger memory corruption bugs in the parser. TensorRT explicitly
warns these files are not safe to load from untrusted sources.
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.5

### CLASS-17: PMML / OpenVINO XML External Entity Injection (HIGH)
**Formats:** .pmml, OpenVINO .xml IR files
**Trigger:** Loading PMML via pypmml, jpmml-evaluator, or OpenVINO model via `core.read_model()`
**Condition:** Attacker supplies a crafted XML model file
**Mechanism:** If the XML parser is not configured with XXE protection (no `resolve_entities=False`
or equivalent), a DOCTYPE with SYSTEM entity can read local files or make SSRF requests.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N = 7.4

### CLASS-18: PaddlePaddle Pickle Deserialization ACE (HIGH)
**Formats:** .pdparams, .pdmodel, paddle checkpoint directories
**Trigger:** `paddle.load(path)`, `paddle.jit.load(path)`
**Condition:** Attacker supplies a crafted PaddlePaddle model file
**Mechanism:** PaddlePaddle uses pickle internally for parameter serialization. `paddle.load()`
on a malicious .pdparams file executes arbitrary code via `__reduce__`.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-19: CoreML Custom Layer Native Code Execution (HIGH)
**Formats:** .mlmodel, .mlpackage (Apple CoreML)
**Trigger:** `coremltools.models.MLModel(model_path)` with custom layer spec
**Condition:** Attacker supplies a CoreML model with a `CustomLayer` or `CustomModel` spec
**Mechanism:** CoreML models can specify custom layers implemented as compiled Swift/Obj-C
frameworks. When loaded on device, the custom framework binary is dlopen'd and executed.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-20: HuggingFace snapshot_download Symlink Following (MEDIUM)
**Formats:** Any files in HuggingFace repos
**Trigger:** `huggingface_hub.snapshot_download(repo_id)` with default `local_dir_use_symlinks=True`
**Condition:** Attacker controls a HuggingFace repo that contains symlinks
**Mechanism:** HuggingFace Hub repositories can contain symlinks. `snapshot_download` follows
these by default, allowing a malicious repo to create symlinks pointing to arbitrary paths
outside the download directory, enabling both reads and writes outside the target directory.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1

### CLASS-21: HuggingFace Model Card YAML ACE (HIGH)
**Formats:** README.md YAML front matter in HuggingFace repos
**Trigger:** Code that parses `README.md` with `yaml.load()` (not `yaml.safe_load()`)
**Condition:** Attacker controls a HuggingFace repo; victim codebase parses its model card
**Mechanism:** YAML `!!python/object/apply` tags execute arbitrary Python when loaded via
`yaml.load()`. If any tooling parses model cards with unsafe YAML loading, arbitrary code runs.
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.5

### CLASS-22: Tokenizer Config Native Code Injection (HIGH)
**Formats:** tokenizer.json (HuggingFace fast tokenizers)
**Trigger:** `AutoTokenizer.from_pretrained(repo)` or `PreTrainedTokenizerFast(tokenizer_file=...)`
**Condition:** Attacker controls the tokenizer.json file
**Mechanism:** HuggingFace's tokenizers library (Rust) supports custom `normalizer`,
`pre_tokenizer`, and `post_processor` types. Certain custom types delegate to registered
Rust callbacks. Crafted tokenizer configs can also inject special tokens that alter LLM
behavior by manipulating how text is split, causing prompt injection or model misbehavior.
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N = 7.1

### CLASS-23: Ray / DeepSpeed Checkpoint Pickle ACE (HIGH)
**Formats:** Ray Tune checkpoints, DeepSpeed checkpoint directories
**Trigger:** `ray.tune.Checkpoint.from_directory()`, `ray.cloudpickle.load()`,
           `deepspeed.utils.zero_to_fp32.get_fp32_unimodel_param_groups_from_zero_checkpoint()`
**Condition:** Attacker supplies a crafted checkpoint directory
**Mechanism:** Ray serializes trial state with cloudpickle (superset of pickle, equally dangerous).
DeepSpeed checkpoints use `torch.save()` (pickle). Malicious checkpoint files execute arbitrary
code on `__reduce__` deserialization.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-24: LoRA / Adapter Weight Output Manipulation (MEDIUM)
**Formats:** adapter_model.safetensors, adapter_model.bin, adapter_config.json
**Trigger:** `PeftModel.from_pretrained(base_model, adapter_path)`, `model.load_adapter()`
**Condition:** Attacker supplies a malicious LoRA adapter; victim applies it to their base model
**Mechanism:** LoRA adapters add low-rank weight matrices to a base model. A malicious adapter
can be crafted to steer model outputs toward attacker-chosen content for specific trigger inputs,
without modifying the base model weights (evades base model scanning). Silent output manipulation.
**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N = 5.9

### CLASS-25: Triton Python Backend Arbitrary Code Execution (HIGH)
**Formats:** Triton model repository (config.pbtxt + model.py)
**Trigger:** Triton Inference Server loading a model with `backend: "python"`
**Condition:** Attacker can place files in the Triton model repository
**Mechanism:** Triton's Python backend loads `model.py` and calls `TritonPythonModel.execute()`.
This is unrestricted Python code execution. If the model repository path is writable or
loaded from an untrusted source, arbitrary code runs in the Triton server context.
**CVSS:** AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9

### CLASS-26: Spark MLlib Java Deserialization ACE (CRITICAL)
**Formats:** Spark ML Pipeline models (saved via `model.save(path)`)
**Trigger:** `PipelineModel.load(path)`, `MLReader.load(path)` in PySpark or Java Spark
**Condition:** Attacker supplies a crafted Spark ML model directory
**Mechanism:** Spark ML uses Java's `ObjectInputStream` for serialization. This is the classic
Java deserialization attack vector — a crafted object graph with `readObject()` gadget chains
(e.g., Commons Collections, Spring Framework) can execute arbitrary OS commands.
**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8

### CLASS-27: TOCTOU Race Condition in Model Validation (MEDIUM)
**Formats:** Any
**Trigger:** Code that validates a model file then loads it from the same mutable path
**Condition:** Attacker can write to the directory containing the model file
**Mechanism:** The validate→load sequence has a race window. Attacker atomically replaces
the validated (safe) model file with a malicious one between validation and load using
`os.rename()` (atomic on POSIX). The loader then reads the malicious file.
**CVSS:** AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H = 6.7

---

## Severity Classification

### Critical (CVSS >= 9.0)
- Unauthenticated RCE via model file load (no user interaction beyond loading the model)
- Pickle ACE where model files come from untrusted internet sources automatically
- GGUF heap overflow leading to confirmed code execution
- Triton Python backend execution in multi-tenant environment
- Spark MLlib Java deserialization with confirmed gadget chain
- trust_remote_code=True where repo_id is user-controlled (no victim interaction needed)

### High (CVSS 7.0–8.9)
- ACE requiring attacker to supply a model file (user interaction = loading the model)
- Keras Lambda ACE through model upload endpoints
- Path injection allowing load of arbitrary local files
- NumPy allow_pickle ACE from untrusted sources
- ONNX custom operator ACE
- MLflow pyfunc ACE on predict()
- PaddlePaddle pickle deserialization
- trust_remote_code=True with hardcoded (but publicly writable) repo
- CoreML custom layer native code execution
- Ray/DeepSpeed checkpoint pickle ACE
- PMML / OpenVINO XXE with file exfiltration
- HuggingFace snapshot symlink following with write capability
- Keras from_config() arbitrary class instantiation
- TensorRT engine memory corruption with demonstrated RCE

### Medium (CVSS 4.0–6.9)
- Zip/TarSlip directory traversal
- SafeTensors integer overflow (crash/DoS, possibly exploitable)
- Inference-time backdoor (silent output manipulation)
- Scanner bypass enabling Medium-severity exploit
- ONNX external data path traversal (file read)
- LoRA adapter output manipulation
- TOCTOU race condition in model validation
- Tokenizer config injection causing prompt manipulation
- HuggingFace model card YAML ACE (if parsing is confirmed)

### Low (CVSS < 4.0)
- DoS via malformed model files (crash without code execution)
- Information disclosure via model metadata (GGUF string metadata)
- Scanner bypass enabling Low-severity exploit
- Unpinned HuggingFace revision (supply chain risk without confirmed compromise)

---

## HuggingFace PoC Guidance

For each confirmed Critical/High finding, provide guidance on creating a HuggingFace PoC:

**Template guidance to include in report:**

```
HuggingFace PoC Setup:
1. Create a HuggingFace account and new repository: huggingface.co/new
2. Generate the malicious model file using the PoC creation code below
3. Upload the model file: huggingface-cli login && huggingface-cli upload <repo> <file>
4. Alternatively, use the HuggingFace web UI to upload the file
5. Victim reproduction: from_pretrained("<your-hf-username>/<repo>") or
   torch.load(hf_hub_download("<your-hf-username>/<repo>", "<filename>"))
6. Observe: [describe the expected impact - command execution, file creation, etc.]

Note: Always use a safe, non-destructive command like `touch /tmp/poc` or
`echo "pwned" > /tmp/poc` in actual PoC files. Never use destructive payloads.
```

---

## Search Patterns Summary

```bash
# Model file extensions (glob)
**/*.pkl **/*.pt **/*.pth **/*.h5 **/*.keras **/*.gguf **/*.safetensors
**/*.onnx **/*.joblib **/*.npy **/*.npz **/*.pb **/*.tflite
**/*.mlmodel **/*.mlpackage **/*.engine **/*.plan **/*.pmml
**/*.pdparams **/*.pdmodel **/*.caffemodel
**/tokenizer.json **/adapter_config.json **/MLmodel **/config.pbtxt

# Unsafe model loading (grep)
torch\.load\s*\( — check for weights_only=False or missing weights_only
pickle\.load|pickle\.loads — always dangerous with untrusted input
np\.load.*allow_pickle.*True — ACE via numpy
joblib\.load\s*\( — pickle-based, same risk as pickle.load
tf\.keras\.models\.load_model|keras\.models\.load_model — Lambda layer risk
tf\.saved_model\.load|hub\.load — custom layer risk
onnxruntime\.InferenceSession — custom op risk
mlflow\.pyfunc\.load_model — ACE on predict()
trust_remote_code\s*=\s*True — downloads + executes Python from HuggingFace
paddle\.load\s*\( — pickle-based PaddlePaddle
trt\.Runtime\(\)\.deserialize_cuda_engine — TensorRT memory corruption
coremltools\.models\.MLModel\( — CoreML custom layer risk
ray\.(tune|train)\.Checkpoint — cloudpickle deserialization
PipelineModel\.load|MLReader\.load — Spark Java deserialization

# Safe loading indicators (these reduce risk — note presence)
weights_only=True — PyTorch safe load
safetensors\.torch\.load_file — safe format
tf\.keras\.models\.load_model.*compile=False — reduces Lambda execution surface
local_dir_use_symlinks=False — safe snapshot_download

# User-controlled model path / repo (grep)
model_path.*=.*request|model.*=.*args\.|hf_hub_download.*user
from_pretrained.*user_input|load_model.*uploaded|load.*user.*path
repo_id.*=.*request|revision.*=.*request|model_name.*=.*args

# GGUF parser patterns (grep in C/C++)
malloc.*n_kv|malloc.*header\.|n_kv\s*\*\s*sizeof|header\.n_tensors\s*\*

# ONNX external data
data_location|load_external_data_for_model|TensorProto.*EXTERNAL

# XML parsing without XXE protection
xml\.etree\.ElementTree\.parse|lxml\.etree\.parse
ElementTree\.fromstring|minidom\.parseString
# Red flag: no defusedxml, no resolve_entities=False
```

---

## Implementation Notes

### Tools to Use
| Task | Tool |
|---|---|
| Clone repo | `Bash` — `git clone` |
| Walk file tree | `Glob` |
| Read source files | `Read` |
| Search patterns | `Grep` |
| Read model files (binary header analysis) | `Bash` — `xxd`, `python3 -c` |
| Write HTML report | `Write` |

### Parallel Analysis
- Launch parallel sub-agents for independent format analyses (e.g., one per model format)
- Run Phase 1 code search and Phase 2 format analysis in parallel after Phase 0 inventory
- Consolidate findings in Phase 4 for verification

### Model File Binary Analysis
When model files are present in the repository, analyze their headers:

```bash
# Check pickle magic bytes in .pkl, .pt, .pth
xxd model.pkl | head -5  # Look for 0x80 0x04/05 (pickle protocol)

# Check GGUF magic
xxd model.gguf | head -2  # Should start with GGUF (47 47 55 46)

# Check SafeTensors header
python3 -c "
import struct, sys
with open('model.safetensors', 'rb') as f:
    n = struct.unpack('<Q', f.read(8))[0]
    print('Header size:', n)
    import json
    header = json.loads(f.read(n))
    print('Metadata:', header.get('__metadata__', {}))
    print('Tensors:', list(header.keys())[:5])
"

# Check Keras HDF5 for Lambda layers
python3 -c "
import h5py, json
with h5py.File('model.h5', 'r') as f:
    config = json.loads(f.attrs['model_config'])
    print(json.dumps(config, indent=2))
" 2>/dev/null | grep -i lambda

# Check ONNX for custom ops and external data
python3 -c "
import onnx
m = onnx.load('model.onnx')
domains = set(n.domain for n in m.graph.node)
print('Domains:', domains)  # Non-empty 'com.example' = custom op
ops = [(n.op_type, n.domain) for n in m.graph.node]
print('Ops:', ops[:20])
# Check for external data references
for init in m.graph.initializer:
    if init.data_location == 1:  # EXTERNAL
        for entry in init.external_data:
            if entry.key == 'location':
                print(f'EXTERNAL DATA: {entry.value}')
"

# Check MLflow model artifact (MLmodel file)
cat MLmodel  # Look for 'python_function' flavor — ACE risk on predict()

# Check PMML / OpenVINO XML for XXE
python3 -c "
import xml.etree.ElementTree as ET
# Safe: ET.parse() is safe by default in Python 3.8+
# But check if the codebase uses lxml with resolve_entities=True
try:
    tree = ET.parse('model.pmml')
    root = tree.getroot()
    print('Root tag:', root.tag)
except Exception as e:
    print('Parse error:', e)
"

# Check HuggingFace tokenizer.json for custom normalizers
python3 -c "
import json
with open('tokenizer.json') as f:
    t = json.load(f)
print('Normalizer:', t.get('normalizer', {}).get('type', 'None'))
print('Pre-tokenizer:', t.get('pre_tokenizer', {}).get('type', 'None'))
print('Post-processor:', t.get('post_processor', {}).get('type', 'None'))
# Flag custom types not in the standard list
standard_types = {'BertNormalizer','ByteLevel','Whitespace','Metaspace',
                  'TemplateProcessing','BPEDecoder','WordPiece','Unigram',
                  'Lowercase','NFD','NFC','NFKD','NFKC','StripAccents',
                  'Prepend','ByteFallback','Fuse','Replace','Strip'}
for k in ['normalizer','pre_tokenizer','post_processor']:
    t_type = t.get(k, {}).get('type', '')
    if t_type and t_type not in standard_types:
        print(f'SUSPICIOUS custom {k} type: {t_type}')
"

# Check LoRA adapter config
python3 -c "
import json
with open('adapter_config.json') as f:
    cfg = json.load(f)
print('Adapter type:', cfg.get('peft_type'))
print('Base model:', cfg.get('base_model_name_or_path'))
print('Target modules:', cfg.get('target_modules'))
print('Modules to save:', cfg.get('modules_to_save'))  # Non-standard saves = risk
"

# Check Triton config for Python backend
grep -i 'backend.*python\|python.*backend' config.pbtxt 2>/dev/null && \
    echo 'PYTHON BACKEND DETECTED — model.py will execute arbitrary code'
```

---

## Ethics & Scope

- This skill performs **static analysis and format inspection only** — no active exploitation
- All PoC code uses non-destructive payloads (`touch /tmp/poc`, not `rm -rf`)
- Findings are for **responsible disclosure** to model repository maintainers
- Do not scan repositories you do not have authorization to audit
- HuggingFace PoC models must be created in your own account, clearly labeled as security
  research, and follow HuggingFace's responsible disclosure process
