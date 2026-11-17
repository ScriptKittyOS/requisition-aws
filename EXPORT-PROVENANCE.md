# Provenance of this repository's first commit

This repository starts from one commit. Its files are, byte for byte, the tree of a reviewed commit of the
project's private repository `requisition-aws`, plus this file:

- private commit: `33862dab6f62bc280a31dfc72e1e62cb39fc784d`
- private tree: `b053a0c8795d60fbfca30d906eb2717e16c127f8`
- exported: 2026-11-17T12:13:39Z

The private repository's history is not part of this repository. Removing this file from the first commit's tree
gives the private tree above exactly (`git write-tree` of the first commit's index without this file prints it).
