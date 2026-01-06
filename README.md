# PurePHP
A native, process-less management console for PHP environments.

## Overview
PurePHP is designed for environments where process execution (exec, system, passthru) is either disabled or heavily monitored by EDR. By utilizing native PHP streams and filesystem functions, PurePHP performs reconnaissance and file management without spawning sub-processes, remaining invisible to many behavioral monitoring tools.

## Features
- In-Memory Execution: Performs full system recon and pivoting using pure PHP logic, avoiding EDR-monitored process calls like system() or exec().
- Gatekeeper Auth: The script remains dormant and invisible to scanners unless triggered by a specific, pre-defined Cookie and POST requirement.
- Network Stack: Integrated socket-based port scanner, service banner grabber, and HTTP fetcher for internal lateral movement.
- Throttled DB Extraction: Minimalist MySQL interface designed for schema enumeration and paged data exfiltration to bypass database audit logs.
- Console History: Export console history to a downloadable text file.

## Usage
### Filesystem
- `dir [path]`
- `stat [path]`
- `read [file]`
- `find [path] [key]`
- `download [file]`
- `upload [path] [b64]`
### Database
- `db_auth [h:p] [u] [p]`
- `db_list [h:p] [u] [p]`
- `db_tables [h:p] [u] [p] [db]`
- `db_query [h:p] [u] [p] [db] [tbl] [pages] [ms]`
### Other
- `fetch [url]`
- `port_scan [h:p]`
- `service_banner [h:p]`
- `dns [target]`
- `self_destruct`

<img width="1437" height="408" alt="image" src="https://github.com/user-attachments/assets/6c6a7f4f-bcaa-440b-9291-28378b085977" />

## OpSec Warning :warning:
While PurePHP avoids process-based detection, network-based actions (like scan or get) will still trigger syscall events (connect). Always use these functions sparingly in high-security environments.

## Disclaimer
This software is provided for educational and ethical security testing purposes only. The author is not responsible for any misuse or damage caused by this tool. Usage of PurePHP for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.
