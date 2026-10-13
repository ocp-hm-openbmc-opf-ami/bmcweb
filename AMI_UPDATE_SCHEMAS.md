# ami_update_schemas.py

A single script that fetches DMTF Redfish schemas and generates all required C++ headers for bmcweb.

## What It Does

| Step | Flag | Output |
|------|------|--------|
| Fetch DMTF schemas | `--update-schemas` | CSDL XMLs → `redfish-core/schema/dmtf/csdl/`, JSON schemas → `redfish-core/schema/dmtf/json-schema/` |
| Generate version map | `--update-version-map` | `redfish-core/include/schema_versions.hpp` — maps schema names to latest versions (DMTF + OEM) |
| Generate enums | `--update-enums` | `redfish-core/include/generated/enums/*.hpp` — C++ enum classes from CSDL EnumType definitions |
| Generate aggregation | `--update-aggregation` | `redfish-core/include/aggregation_utils.hpp` — top-level collection URIs for Redfish Aggregation |

Running with **no flags** executes **all steps**.

## Replaces

- `update_schemas.py` — DMTF schema fetching (now uses git clone instead of zip download)
- `generate_schema_version_map.py` — version map generation
- `schemas.hpp` — dead file that listed schema names without versions

## Usage

```bash
# Run all steps (default)
python3 scripts/ami_update_schemas.py

# Run all steps with custom tag and OEM directories
python3 scripts/ami_update_schemas.py --tag 2026.1 \
    --oem-dirs redfish-core/schema/oem ext/schema/oem

# Run individual steps
python3 scripts/ami_update_schemas.py --update-schemas
python3 scripts/ami_update_schemas.py --update-version-map
python3 scripts/ami_update_schemas.py --update-enums
python3 scripts/ami_update_schemas.py --update-aggregation

# Combine specific steps
python3 scripts/ami_update_schemas.py --update-schemas --update-version-map

# Use a different DMTF tag
python3 scripts/ami_update_schemas.py --update-schemas --tag 2025.4
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--tag` | `2026.1` | DMTF Redfish-Publications git tag to fetch |
| `--repo-url` | `https://github.com/DMTF/Redfish-Publications.git` | DMTF repository URL |
| `--oem-dirs` | `redfish-core/schema/oem`, `ext/schema/oem` | Local OEM schema directories to scan for versions |
| `--version-map-output` | `redfish-core/include/schema_versions.hpp` | Output path for the version map header |
| `--update-schemas` | off | Fetch and install DMTF CSDL and JSON schema files |
| `--update-version-map` | off | Generate `schema_versions.hpp` |
| `--update-enums` | off | Generate enum headers |
| `--update-aggregation` | off | Generate `aggregation_utils.hpp` |

## Version Map Format

The generated `schema_versions.hpp` contains a compile-time map:

```cpp
constexpr std::array<std::pair<std::string_view, std::string_view>, N>
    schemaVersions{{
        {"AccountService", "v1_18_1"},
        {"Chassis", "v1_28_0"},
        {"ChassisCollection", ""},       // unversioned (collection)
        {"AmiSensor", "v1_0_0"},          // OEM schema
    }};
```

- **Versioned schemas** (e.g. `Chassis`) → latest `vX_Y_Z` from CSDL namespaces
- **Unversioned schemas** (e.g. `ChassisCollection`) → empty string `""`
- **OEM schemas** override DMTF if the same name exists

## How Versions Are Extracted

1. Each CSDL XML file contains `<Schema Namespace="...">` elements
2. Versioned namespaces like `Chassis.v1_28_0` are parsed; the highest version tuple wins
3. Unversioned namespaces (no `.vX_Y_Z` suffix, e.g. `ChassisCollection`) are included with an empty version
4. OEM schemas are collected by walking `csdl/` subdirectories under the OEM dirs

## Dependencies

- `generate_schema_enums.py` — called for `--update-enums`
- `generate_schema_collections.py` — called for `--update-aggregation`
- `git` — required for cloning the DMTF repo
