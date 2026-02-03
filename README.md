# jit-sbom

Clone GitHub repo(s), discover manifest files (e.g. `package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`), extract dependencies, resolve each package’s license via public registries, and write JSON (and optionally CSV) with licenses as keys and package lists as values.

## Setup

- Python 3.9+
- Install deps: `pip install -r requirements.txt`

## Commands and defaults

| Option | Default | Description |
|--------|---------|-------------|
| `repo` | *(none)* | Single repo: `owner/repo` or full URL. Omit if using `--repos-file` or `--repos`. |
| `--repos-file`, `-f` | *(none)* | JSON file with array of repo strings, e.g. `["owner/repo", ...]`. |
| `--repos` | *(none)* | Comma-separated repos: `repo1,repo2,...`. |
| `--output-dir`, `-o` | `./results` | Directory for `licenses_<repo_slug>.json` (and `.csv` if `--csv`). |
| `--csv` | off | Also write `licenses_<repo_slug>.csv` (default: JSON only). |

You must provide **one of**: positional `repo`, `--repos-file FILE`, or `--repos repo1,repo2,...`.

## Examples

```bash
# Single repo (output: ./results/licenses_owner-repo.json)
python sbom_licenses.py owner/repo

# Single repo, also write CSV, custom output dir
python sbom_licenses.py owner/repo --csv -o ./out

# Multiple repos from a JSON file
python sbom_licenses.py -f repos.json

# Multiple repos from the command line
python sbom_licenses.py --repos owner/repo1,owner/repo2
```

Cloned repos are temporary and removed after each run. Progress and errors go to stderr.
