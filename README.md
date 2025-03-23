# Mac gurl

This project provides an HTTPAdapter for requests. The adapter will leverage
Apple's [Foundation](https://developer.apple.com/documentation/foundation?language=objc)
and [Security](https://developer.apple.com/documentation/security?language=objc)
framework to perform the HTTP requests. The Python bindings are provided by the
[PyObjC](https://github.com/ronaldoussoren/pyobjc) project. This project is based
on [gurl.py](https://github.com/munki/munki/blob/main/code/client/munkilib/gurl.py)
of the Munki project.

## Important Notes

* Currently only GET requests are supported.

## Usage

```python
import requests
from mac_gurl.requests  import MacHTTPAdapter

s = requests.Session()
s.mount("https:", MacHTTPAdapter())
s.get("YOUR_URL")
```

Details on the HTTPAdapter are described in the [docs of requests](https://requests.readthedocs.io/en/latest/user/advanced/#transport-adapters).

## Run an example script

TODO this needs to be updated

```bash
PYTHONPATH=. uv run example/example.py

# or by sourcing the venv
. .venv/bin/activate
PYTHONPATH=. python example/example.py
```

## Development

### Setup Environment

This project uses [uv](https://github.com/astral-sh/uv) to manage dependencies
and virtual environments.

```bash
uv sync
# activate the virtual environment
. .venv/bin/activate

# check code
ruff check

# format code
ruff format
```
