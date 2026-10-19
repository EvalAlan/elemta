# Licensing

Elemta is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License, version 3** (GPL-3.0-only), as
published by the Free Software Foundation. The full text is in
[LICENSE](LICENSE).

Copyright (C) 2025-2026 Alan Denniston.

## What that means in practice

- You can use Elemta for any purpose, including commercially, and run it
  for yourself or your organisation at no cost.
- You can study and change it.
- If you **distribute** Elemta or software built from it, whether as source,
  binaries, container images or inside a product, you must do so under the
  GPL-3.0 and make the complete corresponding source available to those you
  distribute it to, including your changes.
- You can't combine Elemta into a proprietary program you distribute.

Elemta is provided without any warranty; see sections 15 and 16 of the
license.

## Commercial licenses

If the GPL's terms don't suit you, for example because you want to ship
Elemta inside a closed-source product or appliance, a commercial license is
available from the copyright holder. Open an issue titled "Commercial
license" on GitHub, or contact the maintainer, to discuss it.

## Earlier versions

Versions of Elemta published before this change were released under the MIT
License, and those copies remain available under it. The GPL applies from the
commit that introduced this file onwards.

## Third-party code

Elemta includes adapted copies of two MIT-licensed libraries, kept with their
original license files:

- `internal/imapfork`: [go-imap](https://github.com/emersion/go-imap)
- `internal/sievefork`: [go-sieve](https://github.com/foxcpp/go-sieve)

Other dependencies are used under their own licenses; see `go.mod`.
