<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

$error = null;
$manualConfigContent = null;

if (isset($_SESSION['install_manual_config']) && is_string($_SESSION['install_manual_config'])) {
    $manualConfigContent = $_SESSION['install_manual_config'];
}

$dbDefaults = app_config()['db'] ?? [];
$formDb = [
    'host' => (string) ($dbDefaults['host'] ?? '127.0.0.1'),
    'port' => (string) ($dbDefaults['port'] ?? 3306),
    'name' => (string) ($dbDefaults['name'] ?? 'pixeldust'),
    'user' => (string) ($dbDefaults['user'] ?? 'root'),
    'pass' => (string) ($dbDefaults['pass'] ?? ''),
    'charset' => (string) ($dbDefaults['charset'] ?? 'utf8mb4'),
];

if (is_installed() && $manualConfigContent === null) {
    flash('success', 'Pixel Dust is already installed. Please login.');
    redirect('login.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $passwordConfirm = (string) ($_POST['password_confirm'] ?? '');

    $formDb['host'] = trim((string) ($_POST['db_host'] ?? $formDb['host']));
    $formDb['port'] = trim((string) ($_POST['db_port'] ?? $formDb['port']));
    $formDb['name'] = trim((string) ($_POST['db_name'] ?? $formDb['name']));
    $formDb['user'] = trim((string) ($_POST['db_user'] ?? $formDb['user']));
    $formDb['pass'] = (string) ($_POST['db_pass'] ?? $formDb['pass']);
    $formDb['charset'] = trim((string) ($_POST['db_charset'] ?? $formDb['charset']));

    $dbPort = (int) $formDb['port'];

    if ($username === '' || $password === '') {
        $error = 'Username and password are required.';
    } elseif ($formDb['host'] === '' || $formDb['name'] === '' || $formDb['user'] === '' || $formDb['charset'] === '') {
        $error = 'Database host, name, user, and charset are required.';
    } elseif (!preg_match('/^[A-Za-z0-9_]+$/', $formDb['name'])) {
        $error = 'Database name may only include letters, numbers, and underscores.';
    } elseif (!preg_match('/^[A-Za-z0-9_]+$/', $formDb['charset'])) {
        $error = 'Charset may only include letters, numbers, and underscores.';
    } elseif ($dbPort < 1 || $dbPort > 65535) {
        $error = 'Database port must be between 1 and 65535.';
    } elseif (strlen($username) < 3) {
        $error = 'Username must be at least 3 characters.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters.';
    } elseif ($password !== $passwordConfirm) {
        $error = 'Password confirmation does not match.';
    } else {
        $pdo = null;
        $serverPdo = null;
        try {
            $serverDsn = sprintf(
                'mysql:host=%s;port=%d;charset=%s',
                $formDb['host'],
                $dbPort,
                $formDb['charset']
            );

            $serverPdo = new PDO($serverDsn, $formDb['user'], $formDb['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);

            $serverPdo->exec(
                sprintf(
                    'CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET %s COLLATE %s_general_ci',
                    str_replace('`', '``', $formDb['name']),
                    $formDb['charset'],
                    $formDb['charset']
                )
            );

            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $formDb['host'],
                $dbPort,
                $formDb['name'],
                $formDb['charset']
            );

            $pdo = new PDO($dsn, $formDb['user'], $formDb['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);

            $pdo->beginTransaction();

            run_schema_migrations($pdo);

            $findAdmin = $pdo->prepare('SELECT id FROM pd_admin_users WHERE username = :username LIMIT 1');
            $findAdmin->execute(['username' => $username]);
            $existingAdmin = $findAdmin->fetch();

            if ($existingAdmin) {
                $updateAdmin = $pdo->prepare('UPDATE pd_admin_users SET password_hash = :password_hash WHERE id = :id');
                $updateAdmin->execute([
                    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                    'id' => (int) $existingAdmin['id'],
                ]);
            } else {
                $insertAdmin = $pdo->prepare(
                    'INSERT INTO pd_admin_users (username, password_hash, created_at)
                     VALUES (:username, :password_hash, NOW())'
                );
                $insertAdmin->execute([
                    'username' => $username,
                    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                ]);
            }

            $appConfig = app_config()['app'] ?? [
                'name' => 'Pixel Dust',
                'session_name' => 'pixeldust_session',
                'timezone' => 'UTC',
            ];

            $newConfig = [
                'db' => [
                    'host' => $formDb['host'],
                    'port' => $dbPort,
                    'name' => $formDb['name'],
                    'user' => $formDb['user'],
                    'pass' => $formDb['pass'],
                    'charset' => $formDb['charset'],
                ],
                'app' => $appConfig,
            ];

            $configContent = "<?php\n\nreturn " . var_export($newConfig, true) . ";\n";
            $configPath = __DIR__ . '/_libraries/config.php';

            $pdo->commit();

            if (file_put_contents($configPath, $configContent, LOCK_EX) === false) {
                $_SESSION['install_manual_config'] = $configContent;
                $manualConfigContent = $configContent;
                $error = 'Install completed, but the installer could not write _libraries/config.php. Copy the config block below into that file, then continue to login.';
            } else {
                unset($_SESSION['install_manual_config']);
            }

            if ($manualConfigContent !== null) {
                render_header('Install');
                ?>
                <div class="card">
                    <h1>Install Completed (Manual Config Needed)</h1>
                    <div class="error"><?php echo e($error); ?></div>
                    <p class="muted">Target file: _libraries/config.php</p>
                    <textarea rows="16" readonly onclick="this.select()" style="width:100%;padding:10px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box;font-family:monospace;"><?php echo e($manualConfigContent); ?></textarea>
                    <p style="margin-top:12px;"><a href="login.php">Continue to login</a></p>
                </div>
                <?php
                render_footer();
                exit;
            }

            flash('success', 'Installation completed. Please login.');
            redirect('login.php');
        } catch (Throwable $e) {
            if ($pdo instanceof PDO && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $error = 'Installation failed: ' . $e->getMessage();
        }
    }
}

render_header('Install');
?>
<div class="card">
    <h1>Install Pixel Dust</h1>
    <p class="muted">Configure SQL connection, create database if needed, initialize schema, and create the first admin account.</p>

    <?php if ($error): ?>
        <div class="error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <?php if ($manualConfigContent): ?>
        <div class="card">
            <h2>Manual Config Required</h2>
            <p class="muted">Copy this into _libraries/config.php, then continue to login.</p>
            <textarea rows="12" readonly onclick="this.select()" style="width:100%;padding:10px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box;font-family:monospace;"><?php echo e($manualConfigContent); ?></textarea>
            <p style="margin-top:12px;"><a href="login.php">Continue to login</a></p>
        </div>
    <?php endif; ?>

    <form method="post">
        <h3>Database Settings</h3>
        <div class="row">
            <div>
                <label>Host</label>
                <input type="text" name="db_host" required value="<?php echo e($formDb['host']); ?>">
            </div>
            <div>
                <label>Port</label>
                <input type="number" name="db_port" required min="1" max="65535" value="<?php echo e($formDb['port']); ?>">
            </div>
            <div>
                <label>Database Name</label>
                <input type="text" name="db_name" required value="<?php echo e($formDb['name']); ?>">
            </div>
            <div>
                <label>Database User</label>
                <input type="text" name="db_user" required value="<?php echo e($formDb['user']); ?>">
            </div>
            <div>
                <label>Database Password</label>
                <input type="password" name="db_pass" value="<?php echo e($formDb['pass']); ?>">
            </div>
            <div>
                <label>Charset</label>
                <input type="text" name="db_charset" required value="<?php echo e($formDb['charset']); ?>">
            </div>
        </div>

        <h3 style="margin-top:16px;">Admin Account</h3>
        <div class="row">
            <div>
                <label>Admin Username</label>
                <input type="text" name="username" required minlength="3" value="<?php echo e((string) ($_POST['username'] ?? '')); ?>">
            </div>
            <div>
                <label>Password</label>
                <input type="password" name="password" required minlength="8">
            </div>
            <div>
                <label>Confirm Password</label>
                <input type="password" name="password_confirm" required minlength="8">
            </div>
        </div>
        <p style="margin-top:12px;"><button type="submit">Install Pixel Dust</button></p>
    </form>
</div>
<?php
render_footer();