# KT Overview

KT is a fail-closed, evidence-first system composed of:

- A sealed runtime kernel (`KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`) that enforces determinism, governance, and boundedness.
- An offline growth layer (`KT_PROD_CLEANROOM/tools/growth/`) that measures and produces append-only evidence without mutating the kernel.

Out-of-scope (unless explicitly authorized in a future phase):

- Live provider execution
- Training in runtime
- UI/interactive products

