#!/usr/bin/env python3
"""
Validate if given list of files are encrypted with sops.
"""

import sys

from pre_commit_hook_ensure_sops.hook import main

if __name__ == "__main__":
    sys.exit(main())
