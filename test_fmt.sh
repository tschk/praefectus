#!/bin/bash
set -e
cargo fmt --all
git diff src/lib.rs
