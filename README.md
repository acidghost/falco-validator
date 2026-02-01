# falco-validator

Validate Falco rules with on-demand plugin installation and config generation.

## Features

- **On-demand ruleset loading**: Load rules from falcoctl artifacts or local files
- **Automatic plugin installation**: Extracts plugin dependencies from rules and installs them via falcoctl
- **Dynamic config generation**: Builds Falco configuration on-the-fly with required plugins
- **Flexible input**: Mix and match artifact names and file paths in any order

## Usage

### GitHub Action

Use the falco-validator action to validate your Falco rules in CI/CD pipelines.

#### Basic Example

```yaml
name: Validate Falco Rules

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: acidghost/falco-validator@v1.0.0
        with:
          falco_version: "0.43.0"
          rules: "k8saudit-rules ./my-rules.yaml"
          stable: "true"
```

#### Inputs

| Input           | Required | Default  | Description                                                                      |
| --------------- | -------- | -------- | -------------------------------------------------------------------------------- |
| `falco_version` | Yes      | `0.43.0` | Falco version to use for validation (determines container image tag)             |
| `rules`         | Yes      | -        | Space-separated list of rules to validate (mix of artifact names and file paths) |
| `stable`        | No       | `false`  | Inject Falco stable ruleset                                                      |

#### Examples

Validate multiple artifacts:

```yaml
- uses: acidghost/falco-validator@v1.0.0
  with:
    falco_version: "0.43.0"
    rules: "k8saudit-rules cloudtrail-rules"
```

Validate local files:

```yaml
- uses: acidghost/falco-validator@v1.0.0
  with:
    falco_version: "0.43.0"
    rules: "./rules.yaml ./overrides.yaml"
```

Mix artifacts and files:

```yaml
- uses: acidghost/falco-validator@v1.0.0
  with:
    falco_version: "0.43.0"
    rules: "/etc/falco/falco_rules.yaml k8saudit-rules ./my-overrides.yaml"
    stable: "true"
```

### Container Image

Use the pre-built container image directly with Docker or Podman.

#### Pull the Image

```bash
docker pull ghcr.io/acidghost/falco-validator:v1.0.0-f0.43.0
```

#### Run Validation

```bash
docker run --rm \
  -v ./my-rules.yaml:/rules.yaml:ro \
  ghcr.io/acidghost/falco-validator:v1.0.0-f0.43.0 \
  k8saudit-rules /rules.yaml
```

### Available Falco Versions

Images are available for multiple Falco versions:

| Falco Version | Image Tag                                          |
| ------------- | -------------------------------------------------- |
| 0.42.1        | `ghcr.io/acidghost/falco-validator:v1.0.0-f0.42.1` |
| 0.43.0        | `ghcr.io/acidghost/falco-validator:v1.0.0-f0.43.0` |

### Build from Source

```bash
just build
just build-image
```

## How It Works

1. **Input Processing**: Accepts artifact names (e.g., `k8saudit-rules`) or file paths (e.g., `./rules.yaml`)
2. **Artifact Installation**: For artifacts, uses `falcoctl artifact install` to download and install
3. **Plugin Extraction**: Parses rules YAML files to extract `required_plugin_versions` sections
4. **Deduplication**: Removes duplicate plugins
5. **Config Generation**: Creates `falco.yaml` with required plugin declarations
6. **Rules Combination**: Combines all rules files into a single file
7. **Validation**: Runs `falco -c config.yaml -V combined_rules.yaml` to validate

## License

UNLICENSE - See [UNLICENSE](UNLICENSE) file for details.
