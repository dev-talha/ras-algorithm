<?php
/**
 * Toy RSA Chat Demo - Simple One File Version
 * ------------------------------------------------
 * Educational project only.
 * Real apps should NOT store private keys or plain messages in database.
 * Real apps usually use hybrid encryption: RSA encrypts a symmetric key,
 * and the actual message is encrypted with AES or another symmetric cipher.
 */

session_start();

$dbDir = __DIR__ . '/database';
if (!is_dir($dbDir)) {
    mkdir($dbDir, 0777, true);
}

$dbPath = $dbDir . '/rsa_chat.db';

try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    initDatabase($pdo);
} catch (PDOException $e) {
    showStartupError('SQLite PDO extension/database error', $e->getMessage());
    exit;
}


$page = $_GET['page'] ?? 'home';
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'register') {
        [$error, $success] = handleরেজিস্টার($pdo);
        if (!$error) {
            header('Location: index.php?page=login&registered=1');
            exit;
        }
    }

    if ($action === 'login') {
        [$error, $success] = handleলগইন($pdo);
        if (!$error) {
            header('Location: index.php?page=dashboard');
            exit;
        }
    }

    if ($action === 'send_message') {
        requireলগইন();
        [$error, $success, $receiverId] = handleSendMessage($pdo);
        if (!$error) {
            header('Location: index.php?page=chat&user=' . (int)$receiverId . '&sent=1');
            exit;
        }
        $page = 'chat';
        $_GET['user'] = $receiverId;
    }
}

if ($page === 'logout') {
    session_destroy();
    header('Location: index.php?page=home&logged_out=1');
    exit;
}


function showStartupError(string $title, string $details): void
{
    ?>
    <!doctype html>
    <html lang="bn">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>RSA চ্যাট ডেমো সেটআপ সমস্যা</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+Bengali:wght@400;500;600;700&display=swap" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="card shadow-sm p-4">
                <h2 class="text-danger"><?= e($title) ?></h2>
                <p><?= e($details) ?></p>
                <hr>
                <h5>সমাধানের উপায়</h5>
                <ul>
                    <li>PHP SQLite PDO extension চালু আছে কিনা দেখুন: <code>pdo_sqlite</code>.</li>
                    <li>এই সংস্করণে OpenSSL ব্যবহার করা হয়নি। ছোট শিক্ষামূলক RSA দেখানোর জন্য PHP-এর built-in integer math ব্যবহার করা হয়েছে।</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function initDatabase(PDO $pdo): void
{
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        public_key TEXT NOT NULL,
        private_key TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        plain_message TEXT,
        encrypted_message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )");
}

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function currentUser(PDO $pdo): ?array
{
    if (empty($_SESSION['user_id'])) {
        return null;
    }
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    return $user ?: null;
}

function requireলগইন(): void
{
    if (empty($_SESSION['user_id'])) {
        header('Location: index.php?page=login');
        exit;
    }
}

function gcdInt(int $a, int $b): int
{
    while ($b !== 0) {
        $temp = $b;
        $b = $a % $b;
        $a = $temp;
    }
    return abs($a);
}

function modInverse(int $a, int $m): int
{
    $m0 = $m;
    $x0 = 0;
    $x1 = 1;

    if ($m === 1) {
        return 0;
    }

    while ($a > 1) {
        $q = intdiv($a, $m);
        $temp = $m;
        $m = $a % $m;
        $a = $temp;
        $temp = $x0;
        $x0 = $x1 - $q * $x0;
        $x1 = $temp;
    }

    if ($x1 < 0) {
        $x1 += $m0;
    }

    return $x1;
}

function modPow(int $base, int $exp, int $mod): int
{
    $result = 1;
    $base = $base % $mod;

    while ($exp > 0) {
        if ($exp % 2 === 1) {
            $result = ($result * $base) % $mod;
        }
        $exp = intdiv($exp, 2);
        $base = ($base * $base) % $mod;
    }

    return $result;
}

function generateRSAKeyPair(): array
{
    // OpenSSL ছাড়া ছোট শিক্ষামূলক RSA key তৈরি করা হচ্ছে।
    // এটি বাস্তব নিরাপত্তার জন্য নয়; শুধু class/demo purpose-এর জন্য।
    $primes = [257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349];
    $p = $primes[array_rand($primes)];
    do {
        $q = $primes[array_rand($primes)];
    } while ($q === $p);

    $n = $p * $q;
    $phi = ($p - 1) * ($q - 1);

    $possibleE = [17, 257, 65537, 5, 7, 11, 13];
    $e = 17;
    foreach ($possibleE as $candidate) {
        if ($candidate < $phi && gcdInt($candidate, $phi) === 1) {
            $e = $candidate;
            break;
        }
    }

    $d = modInverse($e, $phi);

    return [
        'public_key' => json_encode(['type' => 'toy-rsa-public', 'n' => $n, 'e' => $e], JSON_PRETTY_PRINT),
        'private_key' => json_encode(['type' => 'toy-rsa-private', 'n' => $n, 'd' => $d, 'p' => $p, 'q' => $q], JSON_PRETTY_PRINT),
    ];
}

function decodeKey(string $key, string $expectedType): array
{
    $data = json_decode($key, true);
    if (!is_array($data) || ($data['type'] ?? '') !== $expectedType) {
        throw new Exception('Key format ঠিক নেই। নতুন করে ব্যবহারকারী নিবন্ধন করে আবার পরীক্ষা করুন।');
    }
    return $data;
}

function encryptMessage(string $plainText, string $publicKey): string
{
    // Receiver-এর public key দিয়ে প্রতিটি UTF-8 byte encrypt করা হচ্ছে।
    $key = decodeKey($publicKey, 'toy-rsa-public');
    $n = (int)$key['n'];
    $e = (int)$key['e'];

    $cipherNumbers = [];
    $bytes = unpack('C*', $plainText);
    foreach ($bytes as $byte) {
        $cipherNumbers[] = modPow((int)$byte, $e, $n);
    }

    return base64_encode(json_encode($cipherNumbers));
}

function decryptMessage(string $encryptedText, string $privateKey): string
{
    try {
        $key = decodeKey($privateKey, 'toy-rsa-private');
        $n = (int)$key['n'];
        $d = (int)$key['d'];

        $json = base64_decode($encryptedText, true);
        $cipherNumbers = $json ? json_decode($json, true) : null;
        if (!is_array($cipherNumbers)) {
            return '[অকার্যকর encrypted text]';
        }

        $plain = '';
        foreach ($cipherNumbers as $number) {
            $plain .= chr(modPow((int)$number, $d, $n));
        }
        return $plain;
    } catch (Exception $e) {
        return '[এই private key দিয়ে decrypt করা যাচ্ছে না]';
    }
}

function handleরেজিস্টার(PDO $pdo): array
{
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($name === '' || $email === '' || $password === '') {
        return ['সব field পূরণ করুন।', ''];
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['সঠিক email দিন।', ''];
    }

    if (strlen($password) < 4) {
        return ['Demo project হলেও password কমপক্ষে ৪ character দিন।', ''];
    }

    try {
        $keys = generateRSAKeyPair();
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare('INSERT INTO users (name, email, password, public_key, private_key) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute([$name, $email, $passwordHash, $keys['public_key'], $keys['private_key']]);

        return ['', 'নিবন্ধন সফল হয়েছে। এখন login করুন।'];
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {
            return ['এই email দিয়ে আগে থেকেই account আছে।', ''];
        }
        return ['Database error: ' . $e->getMessage(), ''];
    } catch (Exception $e) {
        return [$e->getMessage(), ''];
    }
}

function handleলগইন(PDO $pdo): array
{
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        return ['ইমেইল এবং password দিন।', ''];
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password'])) {
        return ['ইমেইল অথবা password ভুল।', ''];
    }

    $_SESSION['user_id'] = $user['id'];
    return ['', 'লগইন সফল হয়েছে।'];
}

function handleSendMessage(PDO $pdo): array
{
    $senderId = (int)$_SESSION['user_id'];
    $receiverId = (int)($_POST['receiver_id'] ?? 0);
    $plainMessage = trim($_POST['message'] ?? '');

    if ($receiverId <= 0) {
        return ['Receiver নির্বাচন করা হয়নি।', '', $receiverId];
    }

    if ($receiverId === $senderId) {
        return ['এই demo-তে নিজের সাথে chat করা যাবে না।', '', $receiverId];
    }

    if ($plainMessage === '') {
        return ['Message লিখুন।', '', $receiverId];
    }

    // RSA সরাসরি long text encrypt করার জন্য উপযুক্ত নয়। তাই demo-তে short message limit রাখা হয়েছে।
    if (strlen($plainMessage) > 500) {
        return ['Message 500 byte-এর মধ্যে রাখুন।', '', $receiverId];
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$receiverId]);
    $receiver = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$receiver) {
        return ['Receiver user পাওয়া যায়নি।', '', $receiverId];
    }

    try {
        $encryptedMessage = encryptMessage($plainMessage, $receiver['public_key']);

        // plain_message শুধু education/demo purpose-এ রাখা হচ্ছে।
        // বাস্তব secure app কখনো database-এ plain message রাখবে না।
        $stmt = $pdo->prepare('INSERT INTO messages (sender_id, receiver_id, plain_message, encrypted_message) VALUES (?, ?, ?, ?)');
        $stmt->execute([$senderId, $receiverId, $plainMessage, $encryptedMessage]);

        return ['', 'Message encrypt করে পাঠানো হয়েছে।', $receiverId];
    } catch (Exception $e) {
        return [$e->getMessage(), '', $receiverId];
    }
}

function getUserById(PDO $pdo, int $id): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    return $user ?: null;
}

function keyPreview(string $key, int $length = 220): string
{
    return strlen($key) > $length ? substr($key, 0, $length) . "\n..." : $key;
}

function renderHeader(PDO $pdo, string $title = 'RSA চ্যাট ডেমো'): void
{
    $user = currentUser($pdo);
    ?>
    <!doctype html>
    <html lang="bn">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title><?= e($title) ?></title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+Bengali:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body { background: #f5f7fb; font-family: "Noto Sans Bengali", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
            .navbar-brand { font-weight: 700; }
            .hero-card { border: 0; border-radius: 20px; box-shadow: 0 8px 25px rgba(0,0,0,.08); }
            .key-box, .encrypted-box { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
            .chat-bubble { border-radius: 18px; padding: 14px; margin-bottom: 14px; }
            .chat-me { background: #dcecff; margin-left: 12%; }
            .chat-other { background: #ffffff; margin-right: 12%; border: 1px solid #e5e7eb; }
            .flow-step { min-height: 105px; }
            .small-muted { font-size: 13px; color: #6b7280; }
            .demo-badge { background: #fff3cd; color: #664d03; border: 1px solid #ffecb5; }
            textarea.form-control { min-height: 110px; }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">RSA চ্যাট ডেমো</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMenu">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navMenu">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="index.php?page=how">RSA কীভাবে কাজ করে</a></li>
                    <?php if ($user): ?>
                        <li class="nav-item"><a class="nav-link" href="index.php?page=dashboard">ড্যাশবোর্ড</a></li>
                        <li class="nav-item"><span class="nav-link text-warning">স্বাগতম, <?= e($user['name']) ?></span></li>
                        <li class="nav-item"><a class="btn btn-outline-light btn-sm mt-1" href="index.php?page=logout">লগআউট</a></li>
                    <?php else: ?>
                        <li class="nav-item"><a class="nav-link" href="index.php?page=login">লগইন</a></li>
                        <li class="nav-item"><a class="btn btn-warning btn-sm mt-1" href="index.php?page=register">রেজিস্টার</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
    <main class="container py-4">
    <?php
}

function renderFooter(): void
{
    ?>
    </main>
    <footer class="container pb-4">
        <div class="text-center small-muted">
             Topic:  RSA Encryption & Decryption
        </div>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
}

function showAlerts(string $error, string $success): void
{
    if ($error) {
        echo '<div class="alert alert-danger">' . e($error) . '</div>';
    }
    if ($success) {
        echo '<div class="alert alert-success">' . e($success) . '</div>';
    }
    if (isset($_GET['registered'])) {
        echo '<div class="alert alert-success">নিবন্ধন সফল হয়েছে। এখন login করুন।</div>';
    }
    if (isset($_GET['sent'])) {
        echo '<div class="alert alert-success">Message receiver-এর public key দিয়ে encrypt হয়ে database-এ সংরক্ষিত হয়েছে।</div>';
    }
    if (isset($_GET['logged_out'])) {
        echo '<div class="alert alert-info">লগআউট সফল হয়েছে।</div>';
    }
}

renderHeader($pdo);
showAlerts($error, $success);

if ($page === 'home'):
?>
    <div class="row align-items-center g-4">
        <div class="col-lg-6">
            <div class="card hero-card p-4">
                <h1 class="display-6 fw-bold">সহজ RSA সিকিউর চ্যাট ডেমো</h1>
                <p class="lead">এই project-এর মূল লক্ষ্য হলো UI-এর মাধ্যমে public key দিয়ে encryption এবং private key দিয়ে decryption প্রক্রিয়া বোঝানো।</p>
                <p>দুইজন user নিবন্ধন করবে। User A message পাঠালে app সেটি User B-এর <b>public key</b> দিয়ে encrypt করবে। User B login করলে তার <b>private key</b> দিয়ে original message দেখতে পারবে।</p>
                <div class="d-flex gap-2 flex-wrap">
                    <a href="index.php?page=register" class="btn btn-warning">ইউজার তৈরি করুন</a>
                    <a href="index.php?page=login" class="btn btn-dark">লগইন</a>
                    <a href="index.php?page=how" class="btn btn-outline-dark">RSA শিখুন</a>
                </div>
            </div>
        </div>
        <div class="col-lg-6">
            <div class="row g-3">
                <div class="col-12"><div class="card p-3 flow-step"><b>১. Plain Message</b><br><span class="small-muted">User A: “Hello B”</span></div></div>
                <div class="col-12"><div class="card p-3 flow-step"><b>২. Encrypt</b><br><span class="small-muted">User B-এর public key ব্যবহার করা হয়।</span></div></div>
                <div class="col-12"><div class="card p-3 flow-step"><b>৩. Database</b><br><span class="small-muted">শুধু encrypted unreadable text সংরক্ষণ করা হয়।</span></div></div>
                <div class="col-12"><div class="card p-3 flow-step"><b>৪. Decrypt</b><br><span class="small-muted">User B তার private key দিয়ে original text দেখে।</span></div></div>
            </div>
        </div>
    </div>
<?php
elseif ($page === 'register'):
?>
    <div class="row justify-content-center">
        <div class="col-md-7 col-lg-6">
            <div class="card hero-card p-4">
                <h3>নতুন ব্যবহারকারী নিবন্ধন করুন</h3>
                <p class="small-muted">নিবন্ধন করলেই স্বয়ংক্রিয়ভাবে public key/private key তৈরি হবে। </p>
                <form method="post">
                    <input type="hidden" name="action" value="register">
                    <div class="mb-3">
                        <label class="form-label">নাম</label>
                        <input type="text" name="name" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">ইমেইল</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">পাসওয়ার্ড</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button class="btn btn-warning w-100">নিবন্ধন করুন এবং  RSA Key তৈরি করুন</button>
                </form>
            </div>
        </div>
    </div>
<?php
elseif ($page === 'login'):
?>
    <div class="row justify-content-center">
        <div class="col-md-7 col-lg-5">
            <div class="card hero-card p-4">
                <h3>লগইন</h3>
                <form method="post">
                    <input type="hidden" name="action" value="login">
                    <div class="mb-3">
                        <label class="form-label">ইমেইল</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">পাসওয়ার্ড</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button class="btn btn-dark w-100">লগইন</button>
                </form>
            </div>
        </div>
    </div>
<?php
elseif ($page === 'dashboard'):
    requireলগইন();
    $user = currentUser($pdo);
    $stmt = $pdo->prepare('SELECT id, name, email, public_key, created_at FROM users WHERE id != ? ORDER BY name');
    $stmt->execute([$user['id']]);
    $others = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
    <div class="row g-4">
        <div class="col-lg-5">
            <div class="card hero-card p-4">
                <h3>ড্যাশবোর্ড</h3>
                <p class="mb-1"><b>লগইন করা user:</b> <?= e($user['name']) ?></p>
                <p class="small-muted"><?= e($user['email']) ?></p>
                <hr>
                <h6>আপনার Public Key Preview</h6>
                <div class="key-box bg-light border rounded p-2"><?= e(keyPreview($user['public_key'])) ?></div>
                <p class="small-muted mt-2">এই public key দিয়ে অন্য user আপনাকে encrypted message পাঠাতে পারবে। <a href="https://vmx.link/KSCSM" target="_blank">বিস্তারিত জানুন</a></p>
            </div>
        </div>`
        <div class="col-lg-7">
            <div class="card hero-card p-4">
                <h4>অন্য ইউজারের সাথে চ্যাট</h4>
                <?php if (!$others): ?>
                    <div class="alert alert-info">এখনো অন্য কোনো user নেই। Demo দেখানোর জন্য আরেকজন user নিবন্ধন করুন।</div>
                    <a href="index.php?page=register" class="btn btn-warning">আরেকজন user নিবন্ধন করুন</a>
                <?php else: ?>
                    <div class="list-group">
                        <?php foreach ($others as $other): ?>
                            <a class="list-group-item list-group-item-action d-flex justify-content-between align-items-center" href="index.php?page=chat&user=<?= (int)$other['id'] ?>">
                                <span>
                                    <b><?= e($other['name']) ?></b><br>
                                    <small><?= e($other['email']) ?></small>
                                </span>
                                <span class="btn btn-sm btn-dark">চ্যাট শুরু করুন</span>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
<?php
elseif ($page === 'chat'):
    requireলগইন();
    $user = currentUser($pdo);
    $receiverId = (int)($_GET['user'] ?? ($_POST['receiver_id'] ?? 0));
    $receiver = getUserById($pdo, $receiverId);

    if (!$receiver || $receiver['id'] == $user['id']): ?>
        <div class="alert alert-danger">সঠিক receiver পাওয়া যায়নি।</div>
        <a href="index.php?page=dashboard" class="btn btn-dark">ড্যাশবোর্ডে ফিরে যান</a>
    <?php else:
        $stmt = $pdo->prepare("SELECT m.*, s.name AS sender_name, r.name AS receiver_name
            FROM messages m
            JOIN users s ON s.id = m.sender_id
            JOIN users r ON r.id = m.receiver_id
            WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.created_at ASC, m.id ASC");
        $stmt->execute([$user['id'], $receiver['id'], $receiver['id'], $user['id']]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>
        <div class="row g-4">
            <div class="col-lg-4">
                <div class="card hero-card p-3 mb-3">
                    <h5>RSA প্রক্রিয়ার ধাপ</h5>
                    <ol class="small mb-0">
                        <li>আপনি plain message লিখবেন।</li>
                        <li>App <b><?= e($receiver['name']) ?>-এর public key</b> ব্যবহার করবে।</li>
                        <li>Encrypted text SQLite database-এ সংরক্ষিত হবে।</li>
                        <li>শুধু <b><?= e($receiver['name']) ?>-এর private key</b> এটি decrypt করতে পারবে।</li>
                    </ol>
                </div>
                <div class="card hero-card p-3 mb-3">
                    <h6><?= e($receiver['name']) ?>-এর Public Key Preview</h6>
                    <div class="key-box bg-light border rounded p-2"><?= e(keyPreview($receiver['public_key'], 260)) ?></div>
                    <p class="small-muted mt-2 mb-0">এই key দিয়ে message lock/encrypt হবে।</p>
                </div>
                <div class="card hero-card p-3">
                    <h6>আপনার Private Key Preview</h6>
                    <div class="key-box bg-light border rounded p-2"><?= e(keyPreview($user['private_key'], 260)) ?></div>
                    <p class="small-muted mt-2 mb-0">আপনি receiver হলে এই private key দিয়ে message unlock/decrypt হবে।  <a href="https://vmx.link/KSCSM" target="_blank">বিস্তারিত জানুন</a></p>
                </div>
            </div>

            <div class="col-lg-8">
                <div class="card hero-card p-4 mb-3">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <h3 class="mb-0"><?= e($receiver['name']) ?>-এর সাথে চ্যাট</h3>
                            <span class="small-muted">সংক্ষিপ্ত message পাঠান।</span>
                        </div>
                        <a href="index.php?page=dashboard" class="btn btn-outline-dark btn-sm">ড্যাশবোর্ড</a>
                    </div>

                    <form method="post">
                        <input type="hidden" name="action" value="send_message">
                        <input type="hidden" name="receiver_id" value="<?= (int)$receiver['id'] ?>">
                        <div class="mb-2">
                            <label class="form-label">Plain Message</label>
                            <textarea name="message" class="form-control" maxlength="500" placeholder="উদাহরণ: Hello, this is RSA demo." required></textarea>
                        </div>
                        <button class="btn btn-warning"><?= e($receiver['name']) ?>-এর Public Key দিয়ে Encrypt করে পাঠান</button>
                    </form>
                </div>

                <div class="card hero-card p-4">
                    <h4>চ্যাট হিস্টোরি</h4>
                    <?php if (!$messages): ?>
                        <div class="alert alert-info">এখনো কোনো message নেই। প্রথমে একটি short message পাঠান।</div>
                    <?php endif; ?>

                    <?php foreach ($messages as $msg):
                        $isMine = (int)$msg['sender_id'] === (int)$user['id'];
                        $isReceiver = (int)$msg['receiver_id'] === (int)$user['id'];
                        $decrypted = $isReceiver ? decryptMessage($msg['encrypted_message'], $user['private_key']) : null;
                    ?>
                        <div class="chat-bubble <?= $isMine ? 'chat-me' : 'chat-other' ?>">
                            <div class="d-flex justify-content-between">
                                <b><?= e($msg['sender_name']) ?> → <?= e($msg['receiver_name']) ?></b>
                                <small><?= e($msg['created_at']) ?></small>
                            </div>
                            <hr>
                            <p class="mb-1"><b>Database-এ সংরক্ষিত Encrypted Text:</b></p>
                            <div class="encrypted-box bg-dark text-light rounded p-2 mb-3"><?= e($msg['encrypted_message']) ?></div>

                            <?php if ($isReceiver): ?>
                                <p class="mb-1"><b>আপনার Private Key দিয়ে Decrypt করা Message:</b></p>
                                <div class="alert alert-success mb-0"><?= e($decrypted) ?></div>
                            <?php else: ?>
                                <p class="mb-1"><b>Sender-এর demo view:</b></p>
                                <div class="alert alert-secondary mb-0">
                                    Original message ছিল: <b><?= e($msg['plain_message']) ?></b><br>
                                    <small>Note: Sender-এর private key দিয়ে এটি decrypt হবে না, কারণ message receiver-এর public key দিয়ে encrypt করা হয়েছে।</small>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    <?php endif; ?>
<?php
elseif ($page === 'how'):
?>
    <div class="card hero-card p-4">
        <h2>RSA কীভাবে কাজ করে - সহজ ব্যাখ্যা</h2>
        <p>RSA হলো public key cryptography। এখানে প্রতিটি user-এর দুটি key থাকে:</p>
        <div class="row g-3 my-3">
            <div class="col-md-6">
                <div class="card p-3 h-100">
                    <h5>Public Key</h5>
                    <p class="mb-0">এটি সবার সাথে share করা যায়। কেউ আপনাকে secret message পাঠাতে চাইলে এই key দিয়ে message encrypt/lock করে।</p>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card p-3 h-100">
                    <h5>Private Key</h5>
                    <p class="mb-0">এটি secret রাখতে হয়। Public key দিয়ে lock করা message শুধু matching private key দিয়ে unlock/decrypt হয়।</p>
                </div>
            </div>
        </div>
        <h4>এই app-এ কী হচ্ছে?</h4>
        <ol>
            <li>User নিবন্ধন করলে app তার RSA public key এবং private key তৈরি করে।</li>
            <li>আপনি কোনো user-কে message পাঠালে app সেই user-এর public key দিয়ে message encrypt করে।</li>
            <li>Database-এ encrypted unreadable text সংরক্ষণ হয়।</li>
            <li>Receiver login করলে তার private key দিয়ে message decrypt হয়ে original text দেখায়।</li>
        </ol>
        <div class="alert alert-warning">
            <b>Security note:</b> এটি শুধু learning project। বাস্তব app-এ private key plain text হিসেবে database-এ রাখা উচিত নয়, plain message সংরক্ষণ করা উচিত নয়, HTTPS ব্যবহার করতে হয়, এবং RSA সাধারণত সরাসরি long message encrypt করে না। Real system-এ hybrid encryption ব্যবহার করা হয়।
        </div>
        <a href="index.php?page=dashboard" class="btn btn-dark">ড্যাশবোর্ডে যান</a>
    </div>
<?php
else:
?>
    <div class="alert alert-danger">পেজ পাওয়া যায়নি.</div>
<?php
endif;

renderFooter();
