# PurePHP
A native, process-less management console for PHP environments.

## Overview
PurePHP is designed for environments where process execution (exec, system, passthru) is either disabled or heavily monitored by EDR. By utilizing native PHP streams and filesystem functions, PurePHP performs reconnaissance and file management without spawning sub-processes, remaining invisible to many behavioral monitoring tools.

## Features
- Zero-Process Recon: Uses scandir and file_get_contents to bypass execve auditing.
- Stealth Gatekeeping: Access is restricted via a custom parameter.
- Native Network Triage: Built-in TCP port scanner using fsockopen.

## Usage
- `dir [path]`
- `read [file]`
- `get [file]`
- `put [path] [b64]`
- `find [path] [key]`
- `stat [path]`
- `scan [h:p]`
- `banner [h:p]`
- `db_test [h:p] [u] [p]`
- `dns [target]`
- `fetch [url]`
- `clear`
- `self_destruct`

## OpSec Warning :warning:
While PurePHP avoids process-based detection, network-based actions (like scan or get) will still trigger syscall events (connect). Always use these functions sparingly in high-security environments.

## Disclaimer
This software is provided for educational and ethical security testing purposes only. The author is not responsible for any misuse or damage caused by this tool. Usage of PurePHP for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.
