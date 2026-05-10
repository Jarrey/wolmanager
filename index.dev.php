<?php
/**
 * Wake on LAN Manager — 网络唤醒管理器
 * Single-file PHP application
 */

session_start();

define('DATA_FILE',  __DIR__ . '/wol_devices.json');
define('USERS_FILE', __DIR__ . '/wol_users.json');

// ── User management ──────────────────────────────────────────────────────
function loadUsers(): array {
    if (!file_exists(USERS_FILE)) {
        $defaults = [[
            'username'      => 'admin',
            'password_hash' => password_hash('admin', PASSWORD_DEFAULT),
            'must_change'   => true,
        ]];
        @file_put_contents(USERS_FILE, json_encode($defaults, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        return $defaults;
    }
    $content = @file_get_contents(USERS_FILE);
    return $content !== false ? (json_decode($content, true) ?: []) : [];
}

function saveUsers(array $users): bool {
    return @file_put_contents(
        USERS_FILE,
        json_encode(array_values($users), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)
    ) !== false;
}

function currentUser(): ?array {
    if (empty($_SESSION['wol_user'])) return null;
    foreach (loadUsers() as $u) {
        if ($u['username'] === $_SESSION['wol_user']) return $u;
    }
    return null;
}

function loadDevices(): array {
    if (!file_exists(DATA_FILE)) return [];
    $content = @file_get_contents(DATA_FILE);
    return $content !== false ? (json_decode($content, true) ?: []) : [];
}

function saveDevices(array $devices): bool {
    return @file_put_contents(
        DATA_FILE,
        json_encode(array_values($devices), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)
    ) !== false;
}

function validateMac(string $mac): bool {
    $clean = preg_replace('/[^0-9A-Fa-f]/', '', $mac);
    return strlen($clean) === 12;
}

function normalizeMac(string $mac): string {
    $hex = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $mac));
    return implode(':', str_split($hex, 2));
}

function sendMagicPacket(string $mac, string $broadcast, int $port): bool {
    $hex = preg_replace('/[^0-9A-Fa-f]/', '', $mac);
    if (strlen($hex) !== 12) return false;

    $packet = str_repeat("\xFF", 6);
    $macBytes = pack('H*', $hex);
    $packet .= str_repeat($macBytes, 16);

    // Try PHP socket extension first
    if (function_exists('socket_create')) {
        $sock = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock !== false) {
            @socket_set_option($sock, SOL_SOCKET, SO_BROADCAST, 1);
            $len = strlen($packet);
            $sent = @socket_sendto($sock, $packet, $len, 0, $broadcast, $port);
            @socket_close($sock);
            if ($sent === $len) return true;
        }
    }

    // Fallback: UDP via stream wrapper
    $sock = @stream_socket_client("udp://{$broadcast}:{$port}", $errno, $errstr, 3);
    if ($sock) {
        stream_set_blocking($sock, false);
        fwrite($sock, $packet);
        fclose($sock);
        return true;
    }

    return false;
}

function pingHost(string $ip): array {
    $escaped = escapeshellarg($ip);
    $start = microtime(true);
    if (PHP_OS_FAMILY === 'Windows') {
        @exec("ping -n 1 -w 1000 {$escaped}", $out, $code);
    } else {
        @exec("ping -c 1 -W 2 {$escaped}", $out, $code);
    }
    $online = ($code === 0);

    // Windows 防火墙默认屏蔽 ICMP，ping 失败时尝试 TCP 端口探测
    if (!$online) {
        foreach ([135, 445, 3389, 139] as $port) {
            $conn = @fsockopen($ip, $port, $errno, $errstr, 1);
            if ($conn !== false) {
                fclose($conn);
                $online = true;
                break;
            }
        }
    }

    return [
        'online' => $online,
        'ms'     => round((microtime(true) - $start) * 1000),
    ];
}

// ── AJAX Handler ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');

    $action  = $_POST['action'];

    // Only 'login' is allowed without authentication
    if ($action !== 'login' && !currentUser()) {
        echo json_encode(['ok' => false, 'msg' => '未登录', 'redirect' => true]);
        exit;
    }

    $devices = loadDevices();

    switch ($action) {

        case 'add':
        case 'edit':
            $name      = substr(trim($_POST['name']      ?? ''), 0, 100);
            $mac       = trim($_POST['mac']       ?? '');
            $ip        = trim($_POST['ip']        ?? '');
            $broadcast = trim($_POST['broadcast'] ?? '255.255.255.255') ?: '255.255.255.255';
            $port      = max(1, min(65535, intval($_POST['port'] ?? 9)));
            $notes     = substr(trim($_POST['notes'] ?? ''), 0, 200);

            if ($name === '') {
                echo json_encode(['ok' => false, 'msg' => '设备名称不能为空']);
                exit;
            }
            if (!validateMac($mac)) {
                echo json_encode(['ok' => false, 'msg' => '无效的 MAC 地址（需要 12 位十六进制字符，如 AA:BB:CC:DD:EE:FF）']);
                exit;
            }
            if ($ip !== '' && !filter_var($ip, FILTER_VALIDATE_IP)) {
                echo json_encode(['ok' => false, 'msg' => '无效的 IP 地址格式']);
                exit;
            }
            if (!filter_var($broadcast, FILTER_VALIDATE_IP)) {
                $broadcast = '255.255.255.255';
            }

            $mac = normalizeMac($mac);

            if ($action === 'add') {
                $devices[] = [
                    'id'        => bin2hex(random_bytes(8)),
                    'name'      => $name,
                    'mac'       => $mac,
                    'ip'        => $ip,
                    'broadcast' => $broadcast,
                    'port'      => $port,
                    'notes'     => $notes,
                    'added'     => date('c'),
                    'last_wake' => null,
                ];
                $msg = '✓ 设备已添加';
            } else {
                $id    = $_POST['id'] ?? '';
                $found = false;
                foreach ($devices as &$dev) {
                    if ($dev['id'] === $id) {
                        $dev['name']      = $name;
                        $dev['mac']       = $mac;
                        $dev['ip']        = $ip;
                        $dev['broadcast'] = $broadcast;
                        $dev['port']      = $port;
                        $dev['notes']     = $notes;
                        $found = true;
                        break;
                    }
                }
                unset($dev);
                if (!$found) {
                    echo json_encode(['ok' => false, 'msg' => '设备不存在']);
                    exit;
                }
                $msg = '✓ 设备已更新';
            }

            echo json_encode(
                saveDevices($devices)
                    ? ['ok' => true, 'msg' => $msg, 'devices' => array_values($devices)]
                    : ['ok' => false, 'msg' => '保存失败，请检查目录写入权限']
            );
            break;

        case 'delete':
            $id     = $_POST['id'] ?? '';
            $before = count($devices);
            $devices = array_values(array_filter($devices, fn($d) => $d['id'] !== $id));
            if (count($devices) === $before) {
                echo json_encode(['ok' => false, 'msg' => '设备未找到']);
                exit;
            }
            echo json_encode(
                saveDevices($devices)
                    ? ['ok' => true, 'msg' => '✓ 设备已删除']
                    : ['ok' => false, 'msg' => '删除失败']
            );
            break;

        case 'wake':
            $id = $_POST['id'] ?? '';
            foreach ($devices as &$dev) {
                if ($dev['id'] === $id) {
                    $ok = sendMagicPacket(
                        $dev['mac'],
                        $dev['broadcast'] ?: '255.255.255.255',
                        $dev['port'] ?: 9
                    );
                    if ($ok) {
                        $dev['last_wake'] = date('c');
                        saveDevices($devices);
                    }
                    echo json_encode([
                        'ok'        => $ok,
                        'msg'       => $ok
                            ? "✓ 唤醒包已发送至《{$dev['name']}》"
                            : '发送失败，请检查网络/权限（可能需要 root 或管理员权限）',
                        'last_wake' => $dev['last_wake'] ?? null,
                    ]);
                    exit;
                }
            }
            echo json_encode(['ok' => false, 'msg' => '设备未找到']);
            break;

        case 'status':
            $id = $_POST['id'] ?? '';
            foreach ($devices as $dev) {
                if ($dev['id'] === $id) {
                    if (empty($dev['ip'])) {
                        echo json_encode(['ok' => true, 'online' => null, 'ms' => null]);
                    } else {
                        $r = pingHost($dev['ip']);
                        echo json_encode(['ok' => true, 'online' => $r['online'], 'ms' => $r['ms']]);
                    }
                    exit;
                }
            }
            echo json_encode(['ok' => false, 'msg' => '设备未找到']);
            break;

        case 'login':
            $username = substr(trim($_POST['username'] ?? ''), 0, 50);
            $password = $_POST['password'] ?? '';
            foreach (loadUsers() as $u) {
                if ($u['username'] === $username && password_verify($password, $u['password_hash'])) {
                    session_regenerate_id(true);
                    $_SESSION['wol_user'] = $username;
                    echo json_encode(['ok' => true, 'must_change' => !empty($u['must_change'])]);
                    exit;
                }
            }
            usleep(200000); // Uniform delay to prevent timing-based enumeration
            echo json_encode(['ok' => false, 'msg' => '用户名或密码错误']);
            break;

        case 'logout':
            session_unset();
            session_destroy();
            echo json_encode(['ok' => true]);
            break;

        case 'change_credentials':
            $user = currentUser();
            if (!$user) { echo json_encode(['ok' => false, 'msg' => '未登录']); exit; }
            $newUsername = substr(trim($_POST['new_username'] ?? ''), 0, 50);
            $oldPassword = $_POST['old_password'] ?? '';
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPass = $_POST['confirm_password'] ?? '';
            if (!password_verify($oldPassword, $user['password_hash'])) {
                echo json_encode(['ok' => false, 'msg' => '当前密码错误']);
                exit;
            }
            if ($newUsername === '') {
                echo json_encode(['ok' => false, 'msg' => '用户名不能为空']);
                exit;
            }
            if (strlen($newPassword) < 6) {
                echo json_encode(['ok' => false, 'msg' => '新密码至少需要 6 个字符']);
                exit;
            }
            if ($newPassword !== $confirmPass) {
                echo json_encode(['ok' => false, 'msg' => '两次输入的密码不一致']);
                exit;
            }
            $users = loadUsers();
            foreach ($users as $u) {
                if ($u['username'] === $newUsername && $u['username'] !== $user['username']) {
                    echo json_encode(['ok' => false, 'msg' => '用户名已被占用']);
                    exit;
                }
            }
            foreach ($users as &$u) {
                if ($u['username'] === $user['username']) {
                    $u['username']      = $newUsername;
                    $u['password_hash'] = password_hash($newPassword, PASSWORD_DEFAULT);
                    $u['must_change']   = false;
                    break;
                }
            }
            unset($u);
            if (saveUsers($users)) {
                session_unset();
                session_destroy();
                echo json_encode(['ok' => true, 'msg' => '✓ 凭据已更新，请使用新凭据重新登录']);
            } else {
                echo json_encode(['ok' => false, 'msg' => '保存失败，请检查目录写入权限']);
            }
            break;

        default:
            echo json_encode(['ok' => false, 'msg' => '未知操作']);
    }
    exit;
}

// ── Auth gate ────────────────────────────────────────────────────────────
$authUser = currentUser();
if (!$authUser) { ?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 · WOL Manager</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='url(%23g)'/%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%231d4ed8'/%3E%3Cstop offset='1' stop-color='%2306b6d4'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cg stroke='%23fff' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round' fill='none' transform='translate(6,6)'%3E%3Cpath d='M16.36 3.64a9 9 0 1 1-12.73 0'/%3E%3Cline x1='10' y1='0' x2='10' y2='10'/%3E%3C/g%3E%3C/svg%3E">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg0:#070c17;--bg1:#0c1424;--bg2:#111d32;--cb:#1b2d4a;--blue:#3b82f6;--blue-d:#2563eb;--cyan:#06b6d4;--blue-glo:rgba(59,130,246,.35);--red:#f04747;--txt:#dde4f0;--txt2:#8aa2c0;--txt3:#45607e;--t:.18s ease}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg0);color:var(--txt);display:flex;align-items:center;justify-content:center;min-height:100vh;background-image:radial-gradient(ellipse 60% 40% at 20% 20%,rgba(59,130,246,.08) 0%,transparent 60%),radial-gradient(ellipse 50% 40% at 80% 80%,rgba(6,182,212,.06) 0%,transparent 60%)}
.lw{width:100%;max-width:400px;padding:20px}
.lb{background:var(--bg2);border:1px solid var(--cb);border-radius:18px;padding:36px 32px;box-shadow:0 24px 80px rgba(0,0,0,.5)}
.ll{width:54px;height:54px;margin:0 auto 18px;background:linear-gradient(135deg,var(--blue-d),var(--cyan));border-radius:14px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 28px rgba(59,130,246,.45)}
.lt{text-align:center;font-size:1.4rem;font-weight:700;margin-bottom:4px;background:linear-gradient(90deg,#d8e4f5,var(--blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.ls{text-align:center;font-size:.8rem;color:var(--txt3);margin-bottom:28px}
.fg{margin-bottom:16px}
.flbl{display:block;font-size:.8rem;font-weight:500;color:var(--txt2);margin-bottom:5px}
.finp{width:100%;background:var(--bg1);border:1px solid var(--cb);border-radius:8px;padding:10px 12px;color:var(--txt);font-size:.9rem;outline:none;transition:border-color var(--t),box-shadow var(--t)}
.finp:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(59,130,246,.14)}
.finp::placeholder{color:var(--txt3)}
.lerr{font-size:.82rem;color:var(--red);margin-bottom:12px;min-height:20px}
.bl{width:100%;padding:11px;background:var(--blue);color:#fff;border:none;border-radius:9px;font-size:.95rem;font-weight:600;cursor:pointer;transition:all var(--t);display:flex;align-items:center;justify-content:center;gap:8px}
.bl:hover{background:var(--blue-d);box-shadow:0 4px 20px var(--blue-glo);transform:translateY(-1px)}
.bl:active{transform:none}
.bl:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
.spin{width:16px;height:16px;border-radius:50%;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;animation:rot .6s linear infinite}
@keyframes rot{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="lw">
  <div class="lb">
    <div class="ll">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>
      </svg>
    </div>
    <div class="lt">WOL Manager</div>
    <div class="ls">网络唤醒管理器 · 请登录继续</div>
    <div class="fg">
      <label class="flbl" for="lUser">用户名</label>
      <input class="finp" type="text" id="lUser" placeholder="输入用户名" autocomplete="username" autofocus>
    </div>
    <div class="fg">
      <label class="flbl" for="lPass">密码</label>
      <input class="finp" type="password" id="lPass" placeholder="输入密码" autocomplete="current-password">
    </div>
    <div class="lerr" id="lErr"></div>
    <button class="bl" id="lBtn" onclick="doLogin()">登录</button>
  </div>
</div>
<script>
document.addEventListener('keydown', function(e) { if (e.key === 'Enter') doLogin(); });
async function doLogin() {
  var u = document.getElementById('lUser').value.trim();
  var p = document.getElementById('lPass').value;
  var err = document.getElementById('lErr');
  var btn = document.getElementById('lBtn');
  if (!u || !p) { err.textContent = '请输入用户名和密码'; return; }
  btn.disabled = true;
  btn.innerHTML = '<div class="spin"></div> 登录中…';
  err.textContent = '';
  try {
    var fd = new FormData();
    fd.append('action', 'login'); fd.append('username', u); fd.append('password', p);
    var r = await fetch(location.href, { method: 'POST', body: fd });
    var d = await r.json();
    if (d.ok) { location.reload(); }
    else { err.textContent = d.msg || '登录失败'; btn.disabled = false; btn.innerHTML = '登录'; }
  } catch(e) { err.textContent = '网络请求失败'; btn.disabled = false; btn.innerHTML = '登录'; }
}
</script>
</body>
</html>
<?php exit; }

$mustChange = !empty($authUser['must_change']);
$devices = array_values(loadDevices());
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WOL Manager · 网络唤醒</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='url(%23g)'/%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%231d4ed8'/%3E%3Cstop offset='1' stop-color='%2306b6d4'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cg stroke='%23fff' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round' fill='none' transform='translate(6,6)'%3E%3Cpath d='M16.36 3.64a9 9 0 1 1-12.73 0'/%3E%3Cline x1='10' y1='0' x2='10' y2='10'/%3E%3C/g%3E%3C/svg%3E">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg0:      #070c17;
  --bg1:      #0c1424;
  --bg2:      #111d32;
  --bg3:      #172340;
  --card:     #0e1a2e;
  --cb:       #1b2d4a;
  --ch:       #142240;
  --blue:     #3b82f6;
  --blue-d:   #2563eb;
  --blue-glo: rgba(59,130,246,.35);
  --cyan:     #06b6d4;
  --green:    #10b981;
  --green-d:  rgba(16,185,129,.15);
  --red:      #f04747;
  --red-d:    rgba(240,71,71,.15);
  --amber:    #f59e0b;
  --amber-d:  rgba(245,158,11,.15);
  --txt:      #dde4f0;
  --txt2:     #8aa2c0;
  --txt3:     #45607e;
  --r:        12px;
  --t:        .18s ease;
}

html { font-size: 16px; scroll-behavior: smooth; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, 'Helvetica Neue', sans-serif;
  background: var(--bg0);
  color: var(--txt);
  min-height: 100vh;
  background-image:
    radial-gradient(ellipse 60% 40% at 15% 10%, rgba(59,130,246,.07) 0%, transparent 60%),
    radial-gradient(ellipse 50% 40% at 85% 85%, rgba(6,182,212,.05) 0%, transparent 60%);
}

::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg1); }
::-webkit-scrollbar-thumb { background: var(--cb); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--blue); }

/* ── Header ──────────────────────────────── */
.hdr {
  position: sticky; top: 0; z-index: 100;
  background: rgba(7,12,23,.88);
  backdrop-filter: blur(18px);
  border-bottom: 1px solid var(--cb);
}
.hdr-inner {
  max-width: 1440px; margin: 0 auto;
  padding: 0 28px; height: 62px;
  display: flex; align-items: center; justify-content: space-between;
}
.logo { display: flex; align-items: center; gap: 12px; }
.logo-mark {
  width: 38px; height: 38px;
  background: linear-gradient(135deg, var(--blue-d), var(--cyan));
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 0 18px rgba(59,130,246,.4);
}
.logo-title {
  font-size: 1.15rem; font-weight: 700; letter-spacing: -.01em;
  background: linear-gradient(90deg, #d8e4f5 0%, var(--blue) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
.logo-sub { font-size: .72rem; color: var(--txt3); margin-top: 1px; }
.hdr-right { display: flex; align-items: center; gap: 10px; }

/* ── Buttons ─────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 15px; border-radius: 8px; border: none;
  cursor: pointer; font-size: .85rem; font-weight: 500;
  transition: all var(--t); white-space: nowrap; outline: none;
}
.btn:disabled { opacity: .45; cursor: not-allowed; pointer-events: none; }
.btn-primary { background: var(--blue); color: #fff; }
.btn-primary:hover { background: var(--blue-d); box-shadow: 0 4px 18px var(--blue-glo); transform: translateY(-1px); }
.btn-success { background: var(--green); color: #fff; }
.btn-success:hover { background: #059669; box-shadow: 0 4px 18px rgba(16,185,129,.35); transform: translateY(-1px); }
.btn-ghost { background: transparent; color: var(--txt2); border: 1px solid var(--cb); }
.btn-ghost:hover { background: var(--bg3); color: var(--txt); border-color: var(--txt3); }
.btn-danger { background: transparent; color: var(--red); border: 1px solid rgba(240,71,71,.3); }
.btn-danger:hover { background: var(--red-d); border-color: var(--red); }
.btn-icon { padding: 7px; background: transparent; color: var(--txt2); border: 1px solid var(--cb); border-radius: 8px; }
.btn-icon:hover { background: var(--bg3); color: var(--txt); border-color: var(--txt3); }
.btn-sm { padding: 5px 11px; font-size: .8rem; border-radius: 6px; }

/* ── Search ──────────────────────────────── */
.srch { position: relative; width: 220px; }
.srch-ico { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--txt3); pointer-events: none; }
.srch input {
  width: 100%; background: var(--card); border: 1px solid var(--cb);
  border-radius: 8px; padding: 7px 10px 7px 32px;
  color: var(--txt); font-size: .85rem; outline: none;
  transition: border-color var(--t);
}
.srch input:focus { border-color: var(--blue); }
.srch input::placeholder { color: var(--txt3); }

/* ── Stats Bar ───────────────────────────── */
.stats { border-bottom: 1px solid var(--cb); }
.stats-inner { display: flex; gap: 14px; padding: 18px 28px; flex-wrap: wrap; max-width: 1440px; margin: 0 auto; }
.stat {
  min-width: 130px; flex: 1; max-width: 180px;
  background: var(--card); border: 1px solid var(--cb);
  border-radius: var(--r); padding: 14px 18px;
  position: relative; overflow: hidden;
}
.stat::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--blue), transparent);
}
.stat.g::before { background: linear-gradient(90deg, var(--green), transparent); }
.stat.a::before { background: linear-gradient(90deg, var(--amber), transparent); }
.stat.r::before { background: linear-gradient(90deg, var(--red), transparent); }
.stat-val { font-size: 1.9rem; font-weight: 700; line-height: 1; color: var(--txt); }
.stat.g .stat-val { color: var(--green); }
.stat.a .stat-val { color: var(--amber); }
.stat.r .stat-val { color: var(--red); }
.stat-lbl { font-size: .7rem; color: var(--txt3); margin-top: 4px; text-transform: uppercase; letter-spacing: .06em; }

/* ── Main ────────────────────────────────── */
.main { padding: 24px 28px; max-width: 1440px; margin: 0 auto; }
.sec-hdr { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; gap: 10px; flex-wrap: wrap; }
.sec-title { font-size: .78rem; font-weight: 600; color: var(--txt3); text-transform: uppercase; letter-spacing: .1em; }

/* ── Device Grid ─────────────────────────── */
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 14px; }

/* ── Device Card ─────────────────────────── */
.card {
  background: var(--card); border: 1px solid var(--cb);
  border-radius: var(--r); padding: 20px;
  transition: all var(--t); position: relative; overflow: hidden;
}
.card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: linear-gradient(90deg, rgba(59,130,246,.4), transparent);
  opacity: 0; transition: opacity var(--t);
}
.card:hover { border-color: rgba(59,130,246,.35); background: var(--ch); transform: translateY(-2px); box-shadow: 0 10px 35px rgba(0,0,0,.35); }
.card:hover::before { opacity: 1; }
.card.st-online { border-color: rgba(16,185,129,.3); }
.card.st-online::before { background: linear-gradient(90deg, rgba(16,185,129,.5), transparent); opacity: 1; }
.card.st-offline { border-color: rgba(240,71,71,.2); }
.card.st-offline::before { background: linear-gradient(90deg, rgba(240,71,71,.35), transparent); opacity: 1; }

.card-top { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 14px; }
.card-info { flex: 1; min-width: 0; }
.card-name { font-size: 1.05rem; font-weight: 600; color: var(--txt); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-note { font-size: .76rem; color: var(--txt3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px; }

/* Status badge */
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 9px; border-radius: 20px; font-size: .72rem;
  font-weight: 500; flex-shrink: 0; margin-left: 8px;
}
.badge-unk { background: rgba(69,96,126,.14); color: var(--txt3); border: 1px solid rgba(69,96,126,.25); }
.badge-on  { background: var(--green-d); color: var(--green); border: 1px solid rgba(16,185,129,.3); }
.badge-off { background: var(--red-d); color: var(--red); border: 1px solid rgba(240,71,71,.22); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; flex-shrink: 0; }
.badge-on .dot { animation: pulse 2.2s infinite; }
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.75)} }

/* Meta grid */
.meta {
  display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px;
  background: rgba(0,0,0,.22); border-radius: 8px;
  padding: 11px 12px; margin-bottom: 14px;
}
.meta-lbl { font-size: .64rem; color: var(--txt3); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 1px; }
.meta-val { font-size: .79rem; color: var(--txt2); font-family: 'SFMono-Regular', Consolas, 'Courier New', monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.meta-val.muted { color: var(--txt3); font-family: inherit; }

/* Actions */
.card-acts { display: flex; gap: 7px; align-items: center; }
.btn-wake {
  flex: 1; background: linear-gradient(135deg, #1d3e8f, var(--blue-d));
  color: #fff; border: none; border-radius: 8px;
  padding: 9px 14px; font-size: .86rem; font-weight: 600;
  cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px;
  transition: all var(--t); letter-spacing: .02em;
}
.btn-wake:hover { background: linear-gradient(135deg, var(--blue-d), var(--blue)); box-shadow: 0 4px 22px rgba(59,130,246,.45); transform: translateY(-1px); }
.btn-wake:active { transform: translateY(0); }
.btn-wake:disabled { opacity: .45; cursor: not-allowed; transform: none; box-shadow: none; }
.last-wake { font-size: .7rem; color: var(--txt3); text-align: center; margin-top: 8px; }

/* Wake flash animation */
@keyframes wakeFlash {
  0%   { box-shadow: none; }
  40%  { box-shadow: 0 0 50px rgba(59,130,246,.7), 0 0 100px rgba(59,130,246,.3), inset 0 0 30px rgba(59,130,246,.1); }
  100% { box-shadow: none; }
}
.card.waking { animation: wakeFlash .8s ease; }

/* ── Empty State ─────────────────────────── */
.empty { text-align: center; padding: 80px 20px; display: none; }
.empty-ico {
  width: 76px; height: 76px; margin: 0 auto 20px;
  background: var(--bg2); border: 2px dashed var(--cb);
  border-radius: 50%; display: flex; align-items: center; justify-content: center;
}
.empty-title { font-size: 1.15rem; font-weight: 600; color: var(--txt2); margin-bottom: 6px; }
.empty-desc { font-size: .875rem; color: var(--txt3); margin-bottom: 22px; }

/* ── Modal ───────────────────────────────── */
.overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,.65);
  backdrop-filter: blur(5px);
  z-index: 200; display: none;
  align-items: center; justify-content: center; padding: 20px;
}
.overlay.open { display: flex; animation: fIn .2s ease; }
@keyframes fIn { from { opacity: 0; } to { opacity: 1; } }

.modal {
  background: var(--bg2); border: 1px solid var(--cb);
  border-radius: 16px; width: 100%; max-width: 490px;
  animation: sUp .22s ease; overflow: hidden;
}
@keyframes sUp { from { opacity: 0; transform: translateY(22px); } to { opacity: 1; transform: translateY(0); } }

.modal-hdr {
  padding: 20px 24px 16px; border-bottom: 1px solid var(--cb);
  display: flex; align-items: center; justify-content: space-between;
}
.modal-title { font-size: 1.05rem; font-weight: 600; }
.modal-close {
  background: none; border: none; color: var(--txt3);
  cursor: pointer; padding: 4px; border-radius: 6px;
  display: flex; transition: all var(--t);
}
.modal-close:hover { color: var(--txt); background: var(--bg3); }
.modal-body { padding: 22px 24px; }
.modal-ftr { padding: 14px 24px; border-top: 1px solid var(--cb); display: flex; justify-content: flex-end; gap: 9px; }

/* Form */
.fg { margin-bottom: 14px; }
.fg:last-child { margin-bottom: 0; }
.flbl { display: block; font-size: .8rem; font-weight: 500; color: var(--txt2); margin-bottom: 5px; }
.flbl em { color: var(--red); margin-left: 2px; font-style: normal; }
.flbl small { color: var(--txt3); font-weight: 400; }
.finp {
  width: 100%; background: var(--bg1); border: 1px solid var(--cb);
  border-radius: 8px; padding: 8px 11px; color: var(--txt);
  font-size: .875rem; outline: none;
  transition: border-color var(--t), box-shadow var(--t);
}
.finp:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(59,130,246,.14); }
.finp::placeholder { color: var(--txt3); }
.fhint { font-size: .72rem; color: var(--txt3); margin-top: 3px; }
.frow { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

/* Confirm modal */
.modal-sm { max-width: 360px; }
.confirm-ico {
  width: 50px; height: 50px; background: var(--red-d);
  border-radius: 50%; display: flex; align-items: center; justify-content: center;
  margin: 0 auto 16px; color: var(--red);
}
.confirm-body { text-align: center; padding: 28px 24px 20px; }
.confirm-ttl { font-size: 1rem; font-weight: 600; margin-bottom: 8px; }
.confirm-txt { font-size: .875rem; color: var(--txt2); line-height: 1.6; }

/* ── Toasts ──────────────────────────────── */
.toasts {
  position: fixed; bottom: 22px; right: 22px; z-index: 1000;
  display: flex; flex-direction: column; gap: 7px; pointer-events: none;
}
.toast {
  background: var(--bg3); border: 1px solid var(--cb);
  border-radius: 10px; padding: 11px 15px;
  display: flex; align-items: center; gap: 10px;
  min-width: 270px; max-width: 370px; pointer-events: auto;
  animation: tIn .28s ease;
  box-shadow: 0 8px 32px rgba(0,0,0,.45);
}
@keyframes tIn  { from { opacity: 0; transform: translateX(18px); } to { opacity: 1; transform: translateX(0); } }
@keyframes tOut { to   { opacity: 0; transform: translateX(18px); height: 0; padding: 0; margin: 0; overflow: hidden; } }
.toast.removing { animation: tOut .25s ease forwards; }
.toast-ico { flex-shrink: 0; font-size: 1rem; }
.toast-msg { font-size: .86rem; color: var(--txt); flex: 1; }
.toast.ok  { border-color: rgba(16,185,129,.4); }
.toast.ok  .toast-ico { color: var(--green); }
.toast.err { border-color: rgba(240,71,71,.4); }
.toast.err .toast-ico { color: var(--red); }
.toast.inf { border-color: rgba(59,130,246,.4); }
.toast.inf .toast-ico { color: var(--blue); }

/* Spinner */
.spin {
  width: 14px; height: 14px; border-radius: 50%;
  border: 2px solid rgba(255,255,255,.25); border-top-color: #fff;
  animation: rot .6s linear infinite; flex-shrink: 0;
}
.spin.sm { width: 12px; height: 12px; border-color: rgba(138,162,192,.3); border-top-color: var(--txt2); }
@keyframes rot { to { transform: rotate(360deg); } }

/* ── Footer ──────────────────────────────── */
.footer { text-align: center; padding: 22px 28px; color: var(--txt3); font-size: .75rem; border-top: 1px solid var(--cb); }
.footer kbd { background: var(--bg3); border: 1px solid var(--cb); border-radius: 4px; padding: 1px 6px; font-size: .72rem; color: var(--txt2); }

/* ── Responsive ─────────────────────────── */
@media (max-width: 640px) {
  .hdr-inner { padding: 0 14px; }
  .logo-sub { display: none; }
  .stats-inner { padding: 10px 14px; gap: 8px; }
  .stat { min-width: 100px; padding: 10px 12px; }
  .stat-val { font-size: 1.4rem; }
  .stat-lbl { font-size: .62rem; }
  .main { padding: 14px; }
  .grid { grid-template-columns: 1fr; }
  .frow { grid-template-columns: 1fr; }
  .srch { width: 120px; }
  .toasts { right: 10px; bottom: 10px; min-width: 0; max-width: calc(100vw - 20px); }
  .hdr-user { display: none; }
}
@media (max-width: 480px) {
  .hdr-inner { padding: 0 10px; }
  .srch { display: none; }
  .hdr-right { gap: 6px; }
  .stat { min-width: 80px; padding: 8px 10px; }
  .stat-val { font-size: 1.2rem; }
  .stat-lbl { font-size: .6rem; }
  .main { padding: 10px; }
  .card { padding: 14px 12px; }
  .meta { gap: 4px 8px; padding: 8px 10px; }
  .meta-val { font-size: .74rem; }
  .meta-lbl { font-size: .6rem; }
  .btn-wake { padding: 8px 10px; font-size: .82rem; }
  .toast { min-width: 180px; }
  .footer { padding: 16px 12px; font-size: .72rem; }
  .sec-hdr { flex-wrap: wrap; gap: 6px; }
}

/* ── Auth UI ─────────────────────────────── */
.hdr-user { font-size: .8rem; max-width: 90px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cred-notice {
  display: flex; align-items: flex-start; gap: 10px;
  background: rgba(245,158,11,.1); border: 1px solid rgba(245,158,11,.3);
  border-radius: 8px; padding: 12px 14px;
  font-size: .82rem; color: #f59e0b; line-height: 1.5; margin-bottom: 16px;
}
</style>
</head>
<body>

<!-- ─ Header ──────────────────────────────────────────────────────────── -->
<header class="hdr">
<div class="hdr-inner">
  <div class="logo">
    <div class="logo-mark">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18.36 6.64a9 9 0 1 1-12.73 0"/>
        <line x1="12" y1="2" x2="12" y2="12"/>
      </svg>
    </div>
    <div>
      <div class="logo-title">WOL Manager</div>
      <div class="logo-sub">网络唤醒管理器</div>
    </div>
  </div>
  <div class="hdr-right">
    <div class="srch">
      <svg class="srch-ico" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      <input type="text" placeholder="搜索设备…" id="srchInp" oninput="filterDevices(this.value)">
    </div>
    <button class="btn btn-primary" onclick="openAddModal()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8">
        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
      </svg>
      添加设备
    </button>
    <button class="btn btn-icon" title="修改凭据" onclick="openCredModal(false)">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
      </svg>
    </button>
    <button class="btn btn-ghost btn-sm" onclick="doLogout()" title="退出登录" style="gap:6px">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
      </svg>
      <span class="hdr-user"><?= htmlspecialchars($authUser['username'], ENT_QUOTES, 'UTF-8') ?></span>
    </button>
  </div>
</div>
</header>

<!-- ─ Stats ───────────────────────────────────────────────────────────── -->
<div class="stats">
<div class="stats-inner">
  <div class="stat">    <div class="stat-val" id="sTotal">0</div>  <div class="stat-lbl">设备总数</div>  </div>
  <div class="stat g"> <div class="stat-val" id="sOnline">—</div> <div class="stat-lbl">在线设备</div> </div>
  <div class="stat r"> <div class="stat-val" id="sOffline">—</div><div class="stat-lbl">离线设备</div></div>
  <div class="stat a"> <div class="stat-val" id="sWake">—</div>   <div class="stat-lbl">上次唤醒</div> </div>
</div>
</div>

<!-- ─ Main ────────────────────────────────────────────────────────────── -->
<main class="main">
  <div class="sec-hdr">
    <span class="sec-title">已管理设备</span>
    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn btn-ghost btn-sm" onclick="checkAll()" id="btnCheckAll">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
        </svg>
        检测全部
      </button>
      <span id="autoTimer" style="font-size:.72rem;color:var(--txt3)"></span>
    </div>
  </div>

  <div class="grid" id="grid"></div>

  <div class="empty" id="empty">
    <div class="empty-ico">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="var(--txt3)" stroke-width="1.5">
        <rect x="2" y="3" width="20" height="14" rx="2"/>
        <line x1="8" y1="21" x2="16" y2="21"/>
        <line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
    </div>
    <div class="empty-title" id="emptyTitle">暂无设备</div>
    <div class="empty-desc"  id="emptyDesc">点击「添加设备」开始管理您的计算机</div>
    <button class="btn btn-primary" id="emptyBtn" onclick="openAddModal()">添加第一台设备</button>
  </div>
</main>

<!-- ─ Footer ──────────────────────────────────────────────────────────── -->
<footer class="footer">
  快捷键：<kbd>Ctrl+N</kbd> 添加 &nbsp;|&nbsp; <kbd>Esc</kbd> 关闭弹窗 &nbsp;·&nbsp;
  数据保存于 <code>wol_devices.json</code>
</footer>

<!-- ─ Add / Edit Modal ────────────────────────────────────────────────── -->
<div class="overlay" id="devOverlay" onclick="bgClose(event,'devOverlay')">
  <div class="modal">
    <div class="modal-hdr">
      <span class="modal-title" id="devTitle">添加设备</span>
      <button class="modal-close" onclick="closeOverlay('devOverlay')" aria-label="关闭">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="fId">
      <div class="fg">
        <label class="flbl">设备名称 <em>*</em></label>
        <input class="finp" type="text" id="fName" placeholder="例：工作站、NAS、家庭电脑" maxlength="100"
               onkeydown="if(event.key==='Enter')saveDevice()">
      </div>
      <div class="fg">
        <label class="flbl">MAC 地址 <em>*</em></label>
        <input class="finp" type="text" id="fMac" placeholder="AA:BB:CC:DD:EE:FF" maxlength="17"
               oninput="fmtMac(this)" onkeydown="if(event.key==='Enter')saveDevice()">
        <div class="fhint">支持 <code>:</code> / <code>-</code> 分隔，或连续输入 12 位十六进制</div>
      </div>
      <div class="frow">
        <div class="fg">
          <label class="flbl">IP 地址 <small>（可选，用于状态检测）</small></label>
          <input class="finp" type="text" id="fIp" placeholder="192.168.1.100">
        </div>
        <div class="fg">
          <label class="flbl">广播地址 <small>（可选）</small></label>
          <input class="finp" type="text" id="fBcast" placeholder="255.255.255.255">
        </div>
      </div>
      <div class="frow">
        <div class="fg">
          <label class="flbl">唤醒端口</label>
          <input class="finp" type="number" id="fPort" placeholder="9" min="1" max="65535" value="9">
        </div>
        <div class="fg">
          <label class="flbl">备注</label>
          <input class="finp" type="text" id="fNotes" placeholder="位置、用途等" maxlength="200">
        </div>
      </div>
    </div>
    <div class="modal-ftr">
      <button class="btn btn-ghost" onclick="closeOverlay('devOverlay')">取消</button>
      <button class="btn btn-primary" id="btnSave" onclick="saveDevice()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
          <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
        </svg>
        保存
      </button>
    </div>
  </div>
</div>

<!-- ─ Confirm Delete Modal ────────────────────────────────────────────── -->
<div class="overlay" id="delOverlay" onclick="bgClose(event,'delOverlay')">
  <div class="modal modal-sm">
    <div class="confirm-body">
      <div class="confirm-ico">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="3 6 5 6 21 6"/>
          <path d="m19 6-.867 12.142A2 2 0 0 1 16.138 20H7.862a2 2 0 0 1-1.995-1.858L5 6m5 0V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v2"/>
        </svg>
      </div>
      <div class="confirm-ttl">删除设备</div>
      <div class="confirm-txt" id="delTxt">确定要删除该设备吗？此操作不可恢复。</div>
    </div>
    <div class="modal-ftr">
      <button class="btn btn-ghost" onclick="closeOverlay('delOverlay')">取消</button>
      <button class="btn btn-danger" id="btnDel">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <polyline points="3 6 5 6 21 6"/>
          <path d="m19 6-.867 12.142A2 2 0 0 1 16.138 20H7.862a2 2 0 0 1-1.995-1.858L5 6m5 0V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v2"/>
        </svg>
        确认删除
      </button>
    </div>
  </div>
</div>

<!-- ─ Change Credentials Modal ───────────────────────────────────────── -->
<div class="overlay" id="credOverlay" onclick="credBgClose(event)">
  <div class="modal">
    <div class="modal-hdr">
      <span class="modal-title">修改登录凭据</span>
      <button class="modal-close" id="credCloseBtn" onclick="closeCredModal()" aria-label="关闭">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>
    </div>
    <div class="modal-body">
      <div class="cred-notice" id="credNotice">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        您仍在使用默认密码，请立即修改用户名和密码以保障访问安全。
      </div>
      <div class="fg">
        <label class="flbl">当前密码 <em>*</em></label>
        <input class="finp" type="password" id="cOldPass" placeholder="输入当前密码" autocomplete="current-password">
      </div>
      <div class="fg">
        <label class="flbl">新用户名 <em>*</em></label>
        <input class="finp" type="text" id="cNewUser" placeholder="输入新用户名" maxlength="50" autocomplete="username">
      </div>
      <div class="fg">
        <label class="flbl">新密码 <em>*</em> <small>（至少 6 位）</small></label>
        <input class="finp" type="password" id="cNewPass" placeholder="输入新密码" autocomplete="new-password">
      </div>
      <div class="fg" style="margin-bottom:0">
        <label class="flbl">确认新密码 <em>*</em></label>
        <input class="finp" type="password" id="cConfPass" placeholder="再次输入新密码" autocomplete="new-password">
      </div>
    </div>
    <div class="modal-ftr">
      <button class="btn btn-ghost" id="credCancelBtn" onclick="closeCredModal()">取消</button>
      <button class="btn btn-primary" id="btnCred" onclick="saveCredentials()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
          <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
        </svg>
        保存修改
      </button>
    </div>
  </div>
</div>

<!-- ─ Toast Container ─────────────────────────────────────────────────── -->
<div class="toasts" id="toasts"></div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
var devices    = <?= json_encode(array_values($devices), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
var mustChange = <?= $mustChange ? 'true' : 'false' ?>;
var stCache    = {};   // { id: { online, ms } }
var srchQ      = '';

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  render();
  updateStats();
  if (mustChange) openCredModal(true);
  // 页面加载后立即检测一次，之后每 5 分钟自动轮询
  checkAllSilent();
  var AUTO_INTERVAL = 5 * 60; // seconds
  var remaining = AUTO_INTERVAL;
  function tick() {
    remaining--;
    if (remaining <= 0) {
      remaining = AUTO_INTERVAL;
      checkAllSilent();
    }
    var m = Math.floor(remaining / 60);
    var s = remaining % 60;
    var el = document.getElementById('autoTimer');
    if (el) el.textContent = '自动检测 ' + m + ':' + (s < 10 ? '0' : '') + s;
  }
  setInterval(tick, 1000);
});

// ── Render all cards ───────────────────────────────────────────────────────
function render() {
  var grid  = document.getElementById('grid');
  var empty = document.getElementById('empty');
  var list  = srchQ
    ? devices.filter(function(d) {
        var q = srchQ;
        return d.name.toLowerCase().indexOf(q) > -1
          || d.mac.toLowerCase().indexOf(q) > -1
          || (d.ip && d.ip.indexOf(q) > -1)
          || (d.notes && d.notes.toLowerCase().indexOf(q) > -1);
      })
    : devices.slice();

  if (list.length === 0) {
    grid.innerHTML = '';
    empty.style.display = 'block';
    if (devices.length > 0 && srchQ) {
      document.getElementById('emptyTitle').textContent = '未找到匹配设备';
      document.getElementById('emptyDesc').textContent  = '没有与「' + srchQ + '」匹配的设备';
      document.getElementById('emptyBtn').style.display = 'none';
    } else {
      document.getElementById('emptyTitle').textContent = '暂无设备';
      document.getElementById('emptyDesc').textContent  = '点击「添加设备」开始管理您的计算机';
      document.getElementById('emptyBtn').style.display = '';
    }
  } else {
    empty.style.display = 'none';
    grid.innerHTML = list.map(cardHtml).join('');
  }
}

function cardHtml(d) {
  var st = stCache[d.id];
  var cls = '', badgeCls = 'badge-unk', badgeTxt = '未检测';
  if (st) {
    if (st.online === null)   { cls = '';          badgeCls = 'badge-unk'; badgeTxt = '无IP'; }
    else if (st.online)       { cls = 'st-online'; badgeCls = 'badge-on';  badgeTxt = '在线' + (st.ms ? ' ' + st.ms + 'ms' : ''); }
    else                      { cls = 'st-offline';badgeCls = 'badge-off'; badgeTxt = '离线'; }
  }
  var lw = d.last_wake ? relTime(d.last_wake) : '从未唤醒';
  var id = esc(d.id);

  return '<div class="card ' + cls + '" id="card-' + id + '">'
    + '<div class="card-top">'
    +   '<div class="card-info">'
    +     '<div class="card-name" title="' + esc(d.name) + '">' + esc(d.name) + '</div>'
    +     (d.notes ? '<div class="card-note">' + esc(d.notes) + '</div>' : '')
    +   '</div>'
    +   '<div class="badge ' + badgeCls + '" id="badge-' + id + '">'
    +     '<span class="dot"></span><span id="badgeTxt-' + id + '">' + esc(badgeTxt) + '</span>'
    +   '</div>'
    + '</div>'
    + '<div class="meta">'
    +   metaItem('MAC 地址', d.mac)
    +   metaItem('IP 地址', d.ip || '<span class="muted">未设置</span>', !d.ip)
    +   metaItem('广播地址', d.broadcast || '255.255.255.255')
    +   metaItem('端口', String(d.port || 9))
    + '</div>'
    + '<div class="card-acts">'
    +   '<button class="btn-wake" id="wbtn-' + id + '" onclick="wakeDevice(\'' + id + '\')">'
    +     '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>'
    +     ' 唤醒'
    +   '</button>'
    +   '<button class="btn btn-icon btn-sm" title="检测状态" id="sbtn-' + id + '" onclick="checkStatus(\'' + id + '\')">'
    +     '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>'
    +   '</button>'
    +   '<button class="btn btn-icon btn-sm" title="编辑设备" onclick="openEditModal(\'' + id + '\')">'
    +     '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>'
    +   '</button>'
    +   '<button class="btn btn-icon btn-sm" title="删除设备" onclick="openDelModal(\'' + id + '\')">'
    +     '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="m19 6-.867 12.142A2 2 0 0 1 16.138 20H7.862a2 2 0 0 1-1.995-1.858L5 6m5 0V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v2"/></svg>'
    +   '</button>'
    + '</div>'
    + '<div class="last-wake">上次唤醒：' + esc(lw) + '</div>'
    + '</div>';
}

function metaItem(label, val, muted) {
  return '<div><div class="meta-lbl">' + label + '</div>'
    + '<div class="meta-val' + (muted ? ' muted' : '') + '">' + (muted ? '未设置' : esc(val)) + '</div></div>';
}

// ── Stats ──────────────────────────────────────────────────────────────────
function updateStats() {
  document.getElementById('sTotal').textContent = devices.length;
  var vals = Object.values(stCache);
  var on   = vals.filter(function(s) { return s.online === true; }).length;
  var off  = vals.filter(function(s) { return s.online === false; }).length;
  document.getElementById('sOnline').textContent  = vals.length ? on  : '—';
  document.getElementById('sOffline').textContent = vals.length ? off : '—';

  var woken = devices.filter(function(d) { return d.last_wake; })
    .sort(function(a,b) { return new Date(b.last_wake) - new Date(a.last_wake); });
  document.getElementById('sWake').textContent = woken.length ? relTime(woken[0].last_wake) : '—';
}

// ── API ────────────────────────────────────────────────────────────────────
async function api(data) {
  var fd = new FormData();
  Object.entries(data).forEach(function(e) { fd.append(e[0], e[1]); });
  var r = await fetch(location.href, { method: 'POST', body: fd });
  return r.json();
}

// ── Wake ───────────────────────────────────────────────────────────────────
async function wakeDevice(id) {
  var btn  = document.getElementById('wbtn-' + id);
  var card = document.getElementById('card-' + id);
  if (!btn) return;

  btn.disabled = true;
  btn.innerHTML = '<div class="spin"></div> 发送中…';

  try {
    var r = await api({ action: 'wake', id: id });
    if (r.ok) {
      toast(r.msg, 'ok');
      card.classList.add('waking');
      card.addEventListener('animationend', function() { card.classList.remove('waking'); }, { once: true });
      var dev = devices.find(function(d) { return d.id === id; });
      if (dev && r.last_wake) { dev.last_wake = r.last_wake; updateStats(); }
    } else {
      toast(r.msg, 'err');
    }
  } catch(e) { toast('网络请求失败', 'err'); }

  btn.disabled = false;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg> 唤醒';
}

// ── Status Check ───────────────────────────────────────────────────────────
async function checkStatus(id) {
  var sbtn  = document.getElementById('sbtn-' + id);
  var badge = document.getElementById('badge-' + id);
  var btxt  = document.getElementById('badgeTxt-' + id);
  var card  = document.getElementById('card-' + id);
  if (sbtn) { sbtn.disabled = true; sbtn.innerHTML = '<div class="spin sm"></div>'; }

  try {
    var r = await api({ action: 'status', id: id });
    if (r.ok) {
      stCache[id] = { online: r.online, ms: r.ms };
      var bCls, bTxt, cAdd;
      if (r.online === null)   { bCls = 'badge-unk'; bTxt = '无IP';                                cAdd = ''; }
      else if (r.online)       { bCls = 'badge-on';  bTxt = '在线' + (r.ms ? ' ' + r.ms + 'ms':''); cAdd = 'st-online'; }
      else                     { bCls = 'badge-off'; bTxt = '离线';                                 cAdd = 'st-offline'; }

      if (badge) badge.className = 'badge ' + bCls;
      if (btxt)  btxt.textContent = bTxt;
      if (card) {
        card.classList.remove('st-online','st-offline');
        if (cAdd) card.classList.add(cAdd);
      }
      updateStats();
    }
  } catch(e) { toast('状态检测失败', 'err'); }

  if (sbtn) {
    sbtn.disabled = false;
    sbtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>';
  }
}

async function checkAll() {
  var btn = document.getElementById('btnCheckAll');
  btn.disabled = true;
  toast('开始检测所有设备状态…', 'inf');
  await Promise.all(devices.map(function(d) { return checkStatus(d.id); }));
  btn.disabled = false;
  toast('全部检测完成', 'ok');
}

async function checkAllSilent() {
  if (devices.length === 0) return;
  await Promise.all(devices.map(function(d) { return checkStatus(d.id); }));
}

// ── Filter ─────────────────────────────────────────────────────────────────
function filterDevices(q) {
  srchQ = q.toLowerCase().trim();
  render();
}

// ── Add / Edit Modal ───────────────────────────────────────────────────────
function openAddModal() {
  document.getElementById('devTitle').textContent = '添加设备';
  document.getElementById('fId').value    = '';
  document.getElementById('fName').value  = '';
  document.getElementById('fMac').value   = '';
  document.getElementById('fIp').value    = '';
  document.getElementById('fBcast').value = '255.255.255.255';
  document.getElementById('fPort').value  = '9';
  document.getElementById('fNotes').value = '';
  openOverlay('devOverlay');
  setTimeout(function() { document.getElementById('fName').focus(); }, 120);
}

function openEditModal(id) {
  var d = devices.find(function(x) { return x.id === id; });
  if (!d) return;
  document.getElementById('devTitle').textContent = '编辑设备';
  document.getElementById('fId').value    = d.id;
  document.getElementById('fName').value  = d.name;
  document.getElementById('fMac').value   = d.mac;
  document.getElementById('fIp').value    = d.ip || '';
  document.getElementById('fBcast').value = d.broadcast || '255.255.255.255';
  document.getElementById('fPort').value  = d.port || 9;
  document.getElementById('fNotes').value = d.notes || '';
  openOverlay('devOverlay');
  setTimeout(function() { document.getElementById('fName').focus(); }, 120);
}

async function saveDevice() {
  var id     = document.getElementById('fId').value;
  var name   = document.getElementById('fName').value.trim();
  var mac    = document.getElementById('fMac').value.trim();
  var ip     = document.getElementById('fIp').value.trim();
  var bcast  = document.getElementById('fBcast').value.trim();
  var port   = document.getElementById('fPort').value;
  var notes  = document.getElementById('fNotes').value.trim();

  if (!name) { toast('请输入设备名称', 'err'); return; }
  if (!mac)  { toast('请输入 MAC 地址', 'err'); return; }

  var btn = document.getElementById('btnSave');
  btn.disabled = true;

  try {
    var r = await api({ action: id ? 'edit' : 'add', id: id, name: name, mac: mac, ip: ip, broadcast: bcast, port: port, notes: notes });
    if (r.ok) {
      devices = r.devices;
      render(); updateStats();
      closeOverlay('devOverlay');
      toast(r.msg, 'ok');
    } else { toast(r.msg, 'err'); }
  } catch(e) { toast('保存失败，请检查网络', 'err'); }

  btn.disabled = false;
}

// ── Delete Modal ───────────────────────────────────────────────────────────
function openDelModal(id) {
  var d = devices.find(function(x) { return x.id === id; });
  document.getElementById('delTxt').textContent = '确定要删除设备「' + (d ? d.name : id) + '」吗？此操作不可恢复。';
  document.getElementById('btnDel').onclick = function() { doDelete(id); };
  openOverlay('delOverlay');
}

async function doDelete(id) {
  try {
    var r = await api({ action: 'delete', id: id });
    if (r.ok) {
      devices = devices.filter(function(d) { return d.id !== id; });
      delete stCache[id];
      render(); updateStats();
      closeOverlay('delOverlay');
      toast(r.msg, 'ok');
    } else { toast(r.msg, 'err'); }
  } catch(e) { toast('删除失败', 'err'); }
}

// ── Overlay helpers ────────────────────────────────────────────────────────
function openOverlay(id)  { document.getElementById(id).classList.add('open'); }
function closeOverlay(id) { document.getElementById(id).classList.remove('open'); }
function bgClose(e, id)   { if (e.target === e.currentTarget) closeOverlay(id); }

// ── MAC formatter ──────────────────────────────────────────────────────────
function fmtMac(inp) {
  var sel = inp.selectionStart;
  var raw = inp.value.replace(/[^0-9A-Fa-f]/g, '').toUpperCase().slice(0, 12);
  var rawBefore = inp.value.slice(0, sel).replace(/[^0-9A-Fa-f]/g, '').length;
  var fmt = (raw.match(/.{1,2}/g) || []).join(':');
  inp.value = fmt;
  // Restore cursor
  var pos = 0, cnt = 0;
  for (var i = 0; i < fmt.length && cnt < rawBefore; i++) {
    if (/[0-9A-F]/i.test(fmt[i])) cnt++;
    pos = i + 1;
  }
  inp.setSelectionRange(pos, pos);
}

// ── Toast ──────────────────────────────────────────────────────────────────
function toast(msg, type) {
  var icons = { ok: '✓', err: '✕', inf: 'ℹ' };
  var el = document.createElement('div');
  el.className = 'toast ' + (type || 'inf');
  el.innerHTML = '<span class="toast-ico">' + (icons[type]||'ℹ') + '</span>'
               + '<span class="toast-msg">' + esc(msg) + '</span>';
  document.getElementById('toasts').appendChild(el);
  setTimeout(function() {
    el.classList.add('removing');
    el.addEventListener('animationend', function() { el.remove(); });
  }, 3800);
}

// ── Utilities ──────────────────────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function relTime(iso) {
  if (!iso) return '从未';
  try {
    var d    = new Date(iso), now = new Date();
    var diff = Math.floor((now - d) / 1000);
    if (diff < 60)      return '刚刚';
    if (diff < 3600)    return Math.floor(diff/60) + ' 分钟前';
    if (diff < 86400)   return Math.floor(diff/3600) + ' 小时前';
    if (diff < 2592000) return Math.floor(diff/86400) + ' 天前';
    return d.toLocaleDateString('zh-CN');
  } catch(e) { return iso; }
}

// ── Credentials modal ────────────────────────────────────────────────────
function openCredModal(forced) {
  document.getElementById('cOldPass').value  = '';
  document.getElementById('cNewUser').value  = '';
  document.getElementById('cNewPass').value  = '';
  document.getElementById('cConfPass').value = '';
  var notice    = document.getElementById('credNotice');
  var closeBtn  = document.getElementById('credCloseBtn');
  var cancelBtn = document.getElementById('credCancelBtn');
  notice.style.display    = forced ? 'flex' : 'none';
  closeBtn.style.display  = forced ? 'none' : '';
  cancelBtn.style.display = forced ? 'none' : '';
  openOverlay('credOverlay');
  setTimeout(function() { document.getElementById('cOldPass').focus(); }, 120);
}

function closeCredModal() {
  if (mustChange) return;
  closeOverlay('credOverlay');
}

function credBgClose(e) {
  if (!mustChange && e.target === e.currentTarget) closeOverlay('credOverlay');
}

async function saveCredentials() {
  var oldPass  = document.getElementById('cOldPass').value;
  var newUser  = document.getElementById('cNewUser').value.trim();
  var newPass  = document.getElementById('cNewPass').value;
  var confPass = document.getElementById('cConfPass').value;
  if (!oldPass) { toast('请输入当前密码', 'err'); return; }
  if (!newUser) { toast('请输入新用户名', 'err'); return; }
  if (!newPass) { toast('请输入新密码', 'err'); return; }
  if (newPass !== confPass) { toast('两次输入的密码不一致', 'err'); return; }

  var btn = document.getElementById('btnCred');
  btn.disabled = true;
  try {
    var r = await api({
      action:           'change_credentials',
      old_password:     oldPass,
      new_username:     newUser,
      new_password:     newPass,
      confirm_password: confPass,
    });
    if (r.ok) {
      toast(r.msg, 'ok');
      setTimeout(function() { location.reload(); }, 1500);
    } else {
      toast(r.msg, 'err');
      btn.disabled = false;
    }
  } catch(e) {
    toast('请求失败', 'err');
    btn.disabled = false;
  }
}

async function doLogout() {
  try { await api({ action: 'logout' }); } catch(e) {}
  location.reload();
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeOverlay('devOverlay');
    closeOverlay('delOverlay');
    if (!mustChange) closeOverlay('credOverlay');
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
    e.preventDefault();
    openAddModal();
  }
});
</script>
</body>
</html>
