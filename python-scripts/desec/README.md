# desec-api.py (legacy)

> **Note:** This is the original monolithic version of the deSEC manager (~2220 lines).
> The actively developed split version lives at [programs/desec](../../programs/desec/).
> Both do the same thing — this one is kept as a reference.

Manage deSEC DNS API tokens, policies, domains, and records from the terminal.  Includes both a TUI (Textual) and a full CLI.

## Requirements

```bash
pip install textual httpx pyyaml
```

## Quick start

```bash
python desec-api.py           # launches TUI; prompts for token on first run
python desec-api.py --help    # CLI reference
```

Config is saved to `~/.config/mech-goodies/desec.env`.

## CLI examples

```bash
python desec-api.py token list
python desec-api.py domain list
python desec-api.py record list example.dedyn.io
python desec-api.py ddns-add example.dedyn.io
python desec-api.py cert-add example.dedyn.io
```

See [programs/desec/README.md](../../programs/desec/README.md) for the full feature reference.
