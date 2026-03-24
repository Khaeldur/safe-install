# Changelog

All notable changes to the "Safe Install" extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-25

### Added
- On-save scanning of dependency files (requirements.txt, package.json, Cargo.toml, go.mod, Gemfile)
- Hover intelligence showing package age, maintainer count, typosquat risk
- Status bar protection indicator (shield icon)
- Commands: Scan Current File, Audit Package Under Cursor, Toggle Protection
- Support for pip, npm, cargo, go, gem ecosystems
