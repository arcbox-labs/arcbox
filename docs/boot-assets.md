# Boot Assets Management Convention

Boot assets in this repository are treated as locally generated/downloaded artifacts and are not committed to the repository.

## Local Generation and Storage
- Generated or downloaded by `scripts/setup-dev-boot-assets.sh`.
- Artifacts are placed in `boot-assets/` or `tests/resources/` directories.

## Release Method
- Versioned artifacts are published to boot-images (external storage/Release).
- Only scripts and documentation are kept in the repository.

## Repository Constraints
- `boot-assets/` and `tests/resources/boot-assets-*` are ignored in `.gitignore`.
