# mitm-addon

## Setup
I added pymongo to the build using `requirements.txt`.  I see that requests is installed during the virtual environment setup, but I might add it again just in case.

## To start

```sh
. venv/bin/activate
mitmdump -s scintillator/scintillator.py
```

ref: https://github.com/mitmproxy/mitmproxy/blob/master/CONTRIBUTING.md