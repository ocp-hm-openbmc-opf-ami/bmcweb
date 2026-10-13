#!/usr/bin/env python3

"""
Combined script that:
1. Fetches DMTF schemas from git (replaces update_schemas.py)
2. Generates schema_versions.hpp (replaces generate_schema_version_map.py)
3. Generates enum headers via generate_schema_enums
4. Generates aggregation_utils.hpp via generate_schema_collections
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import OrderedDict, defaultdict

import generate_schema_enums
from generate_schema_collections import generate_top_collections

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

REPO_URL = "https://github.com/DMTF/Redfish-Publications.git"
DEFAULT_TAG = "2026.1"

redfish_core_path = os.path.join(SCRIPT_DIR, "..", "redfish-core")

schema_path = os.path.join(redfish_core_path, "schema", "dmtf", "csdl")
json_schema_path = os.path.join(
    redfish_core_path, "schema", "dmtf", "json-schema"
)
DEFAULT_OEM_DIRS = [
    os.path.realpath(
        os.path.join(SCRIPT_DIR, "..", "redfish-core", "schema", "oem")
    ),
    os.path.realpath(os.path.join(SCRIPT_DIR, "..", "ext", "schema", "oem")),
]

VERSION_MAP_OUTFILE = os.path.realpath(
    os.path.join(
        SCRIPT_DIR, "..", "redfish-core", "include", "schema_versions.hpp"
    )
)

EDMX = "{http://docs.oasis-open.org/odata/ns/edmx}"
EDM = "{http://docs.oasis-open.org/odata/ns/edm}"
VERSION_RE = re.compile(r"^(.+)\.(v(\d+)_(\d+)_(\d+))$")


class SchemaVersion:
    def __init__(self, key):
        key = str.casefold(key)
        split_tup = key.split(".")
        self.version_pieces = [split_tup[0]]
        if len(split_tup) < 2:
            return
        version = split_tup[1]
        if version.startswith("v"):
            version = version[1:]
        if any(char.isdigit() for char in version):
            self.version_pieces.extend([int(x) for x in version.split("_")])

    def __lt__(self, other):
        return self.version_pieces < other.version_pieces


# ---------------------------------------------------------------------------
# Schema version map generation
# ---------------------------------------------------------------------------


def parse_version_tuple(version_str):
    m = re.match(r"v(\d+)_(\d+)_(\d+)", version_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def extract_latest_versions_from_csdl(csdl_dir):
    schema_versions = {}
    unversioned_schemas = set()

    for filename in sorted(os.listdir(csdl_dir)):
        if not filename.endswith(".xml"):
            continue
        filepath = os.path.join(csdl_dir, filename)
        if os.path.islink(filepath):
            continue
        try:
            tree = ET.parse(filepath)
        except ET.ParseError as e:
            print(f"Warning: Failed to parse {filepath}: {e}", file=sys.stderr)
            continue

        root = tree.getroot()
        ds = root.find(EDMX + "DataServices")
        if ds is None:
            continue

        has_versioned = set()
        has_unversioned = set()

        for schema in ds.findall(EDM + "Schema"):
            namespace = schema.get("Namespace", "")
            m = VERSION_RE.match(namespace)
            if m:
                schema_name = m.group(1)
                version_str = m.group(2)
                version_tuple = (
                    int(m.group(3)),
                    int(m.group(4)),
                    int(m.group(5)),
                )
                has_versioned.add(schema_name)
                existing = schema_versions.get(schema_name)
                if existing is None or version_tuple > existing[1]:
                    schema_versions[schema_name] = (version_str, version_tuple)
            else:
                if (
                    not namespace.startswith("Org.OData")
                    and "." not in namespace
                ):
                    has_unversioned.add(namespace)

        for ns in has_unversioned:
            if ns not in has_versioned:
                unversioned_schemas.add(ns)

    result = {name: info[0] for name, info in schema_versions.items()}
    for name in unversioned_schemas:
        if name not in result:
            result[name] = ""
    return result


def collect_oem_schemas(oem_dirs):
    all_versions = {}
    for oem_dir in oem_dirs:
        if not os.path.isdir(oem_dir):
            print(f"OEM dir not found, skipping: {oem_dir}", file=sys.stderr)
            continue
        for dirpath, dirnames, filenames in os.walk(oem_dir):
            if os.path.basename(dirpath) != "csdl":
                continue
            versions = extract_latest_versions_from_csdl(dirpath)
            for name, ver in versions.items():
                existing = all_versions.get(name)
                if existing is None:
                    all_versions[name] = ver
                else:
                    existing_tuple = parse_version_tuple(existing)
                    new_tuple = parse_version_tuple(ver)
                    if new_tuple and (
                        not existing_tuple or new_tuple > existing_tuple
                    ):
                        all_versions[name] = ver
    return all_versions


def write_version_map_hpp(schema_map, outfile):
    ordered = OrderedDict(sorted(schema_map.items()))
    with open(outfile, "w") as f:
        f.write(
            "// SPDX-License-Identifier: Apache-2.0\n"
            "// SPDX-FileCopyrightText: Copyright AMI Authors\n"
            "#pragma once\n"
            "/****************************************************************\n"
            " *                 READ THIS WARNING FIRST\n"
            " * This is an auto-generated header which contains definitions\n"
            " * for Redfish DMTF defined schemas.\n"
            " * DO NOT modify this file outside of running the\n"
            " * ami_update_schemas.py script.\n"
            " ***************************************************************/\n"
            "// clang-format off\n"
            "#include <array>\n"
            "#include <string_view>\n"
            "#include <utility>\n"
            "\n"
            "namespace redfish\n"
            "{\n"
            "namespace schema\n"
            "{\n"
            "\n"
            "// Map of schema name to its latest version string.\n"
            "// e.g. {\"Chassis\", \"v1_26_0\"} means the @odata.type would be\n"
            "// \"#Chassis.v1_26_0.Chassis\"\n"
            "// constexpr array of pairs avoids heap allocation overhead of unordered_map\n"
            f"constexpr std::array<std::pair<std::string_view, std::string_view>, {len(ordered)}>\n"
            "    schemaVersions{{\n"
        )
        for name, version in ordered.items():
            f.write(f'        {{"{name}", "{version}"}},\n')
        f.write(
            "}};\n"
            "\n"
            "} // namespace schema\n"
            "} // namespace redfish\n"
            "// clang-format on\n"
        )
    print(f"Generated {outfile} with {len(ordered)} entries.")


# ---------------------------------------------------------------------------
# DMTF schema fetch + install (from update_schemas.py)
# ---------------------------------------------------------------------------


def fetch_and_install_dmtf_schemas(repo_dir):
    repo_csdl_dir = os.path.join(repo_dir, "csdl")
    repo_json_dir = os.path.join(repo_dir, "json-schema")

    shutil.rmtree(schema_path)
    os.makedirs(schema_path)

    shutil.rmtree(json_schema_path)
    os.makedirs(json_schema_path)

    csdl_filenames = sorted(os.listdir(repo_csdl_dir))

    json_schema_files = defaultdict(list)
    for filename in os.listdir(repo_json_dir):
        json_schema_files[filename.split(".")[0]].append(filename)

    for value in json_schema_files.values():
        value.sort(key=SchemaVersion, reverse=True)

    json_schema_files = OrderedDict(
        sorted(
            json_schema_files.items(), key=lambda x: SchemaVersion(x[0])
        )
    )

    for csdl_file in csdl_filenames:
        shutil.copy(
            os.path.join(repo_csdl_dir, csdl_file),
            os.path.join(schema_path, csdl_file),
        )

    for schema_filename, versions in json_schema_files.items():
        shutil.copy(
            os.path.join(repo_json_dir, versions[0]),
            os.path.join(json_schema_path, versions[0]),
        )

    print(
        f"Installed {len(csdl_filenames)} CSDL and "
        f"{len(json_schema_files)} JSON schema files."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Fetch DMTF schemas and generate schema_versions.hpp, "
        "enum headers, and aggregation_utils.hpp. "
        "By default all steps run. Use flags to run only specific steps."
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_TAG,
        help=f"DMTF Redfish-Publications git tag (default: {DEFAULT_TAG})",
    )
    parser.add_argument(
        "--repo-url",
        default=REPO_URL,
        help=f"DMTF repo URL (default: {REPO_URL})",
    )
    parser.add_argument(
        "--oem-dirs",
        nargs="*",
        default=DEFAULT_OEM_DIRS,
        help="Local OEM schema directories to scan",
    )
    parser.add_argument(
        "--version-map-output",
        default=VERSION_MAP_OUTFILE,
        help=f"Output path for schema_versions.hpp "
        f"(default: {VERSION_MAP_OUTFILE})",
    )
    parser.add_argument(
        "--update-schemas",
        action="store_true",
        help="Fetch and install DMTF CSDL and JSON schema files",
    )
    parser.add_argument(
        "--update-version-map",
        action="store_true",
        help="Generate schema_versions.hpp",
    )
    parser.add_argument(
        "--update-enums",
        action="store_true",
        help="Generate enum headers from CSDL schemas",
    )
    parser.add_argument(
        "--update-aggregation",
        action="store_true",
        help="Generate aggregation_utils.hpp (top collections)",
    )
    args = parser.parse_args()

    # If no specific step is selected, run all steps
    run_all = not any([
        args.update_schemas,
        args.update_version_map,
        args.update_enums,
        args.update_aggregation,
    ])

    needs_clone = run_all or args.update_schemas or args.update_version_map

    dmtf_versions = {}
    if needs_clone:
        with tempfile.TemporaryDirectory() as repo_dir:
            print(f"Cloning {args.repo_url} at tag {args.tag} ...")
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "--branch",
                    args.tag,
                    args.repo_url,
                    repo_dir,
                ],
                check=True,
            )

            if run_all or args.update_schemas:
                fetch_and_install_dmtf_schemas(repo_dir)

            if run_all or args.update_version_map:
                csdl_dir = os.path.join(repo_dir, "csdl")
                if os.path.isdir(csdl_dir):
                    dmtf_versions = extract_latest_versions_from_csdl(csdl_dir)
                    print(f"Found {len(dmtf_versions)} DMTF schemas.")

    if run_all or args.update_version_map:
        oem_versions = collect_oem_schemas(args.oem_dirs)
        print(f"Found {len(oem_versions)} OEM schemas.")

        merged = {}
        merged.update(dmtf_versions)
        merged.update(oem_versions)
        print(f"Total unique schemas: {len(merged)}")
        write_version_map_hpp(merged, args.version_map_output)

    if run_all or args.update_enums:
        print("Generating schema enums...")
        generate_schema_enums.main()

    if run_all or args.update_aggregation:
        print("Generating top collections...")
        generate_top_collections()

    print("Done.")


if __name__ == "__main__":
    main()
