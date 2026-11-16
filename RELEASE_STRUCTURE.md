# Release Structure

## GitHub repository

Recommended GitHub content:

- top-level README;
- documentation;
- frozen reproducibility code;
- final sample-selection reproduction package;
- frozen manifests/contracts/schemas;
- small derived result tables;
- script-retention/curation ledgers;
- CITATION.cff;
- licensing;
- dataset DOI/link;
- checksum/manifest files for repository content.

The multi-gigabyte telemetry dataset should not be stored in ordinary Git
history.

## DOI data repository

Recommended DOI-bearing dataset content:

- successful benign preflight packages;
- successful ransomware preflight packages;
- 100 official run evidence packages;
- dataset manifest;
- full SHA-256 release inventory;
- data dictionary;
- dataset README;
- provenance/safety documents.

## Cross-linking

The GitHub release should cite the dataset DOI.

The dataset record should link back to the exact tagged GitHub software
release used for analysis.

Both releases should identify the same publication/version label.

