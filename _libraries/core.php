<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

date_default_timezone_set($config['app']['timezone'] ?? 'UTC');

if (session_status() === PHP_SESSION_NONE) {
	session_name($config['app']['session_name'] ?? 'pixeldust_session');
	session_start();
}

function app_config(): array
{
	global $config;
	return $config;
}

function db(): PDO
{
	static $pdo = null;

	if ($pdo instanceof PDO) {
		return $pdo;
	}

	$cfg = app_config()['db'];
	$dsn = sprintf(
		'mysql:host=%s;port=%d;dbname=%s;charset=%s',
		$cfg['host'],
		(int) $cfg['port'],
		$cfg['name'],
		$cfg['charset']
	);

	$pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
		PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
	]);

	return $pdo;
}

function is_installed(): bool
{
	try {
		$stmt = db()->query("SHOW TABLES LIKE 'pd_admin_users'");
		if (!$stmt->fetch()) {
			return false;
		}

		$countStmt = db()->query('SELECT COUNT(*) AS total FROM pd_admin_users');
		$row = $countStmt->fetch();
		return (int) ($row['total'] ?? 0) > 0;
	} catch (Throwable $e) {
		return false;
	}
}

function base_url(): string
{
	$isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
	$scheme = $isHttps ? 'https' : 'http';
	$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
	$scriptDir = dirname($_SERVER['SCRIPT_NAME'] ?? '/pixeldust/index.php');

	if (strpos($scriptDir, '/admin') !== false) {
		$scriptDir = dirname($scriptDir);
	}

	return rtrim($scheme . '://' . $host . rtrim($scriptDir, '/'), '/');
}

function e(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function redirect(string $path): void
{
	header('Location: ' . $path);
	exit;
}

function flash(string $key, ?string $message = null): ?string
{
	if ($message !== null) {
		$_SESSION['flash'][$key] = $message;
		return null;
	}

	if (!isset($_SESSION['flash'][$key])) {
		return null;
	}

	$msg = (string) $_SESSION['flash'][$key];
	unset($_SESSION['flash'][$key]);
	return $msg;
}

function current_admin(): ?array
{
	if (empty($_SESSION['admin_user_id'])) {
		return null;
	}

	$stmt = db()->prepare('SELECT id, username, created_at, last_login_at FROM pd_admin_users WHERE id = :id LIMIT 1');
	$stmt->execute(['id' => (int) $_SESSION['admin_user_id']]);
	$admin = $stmt->fetch();

	return $admin ?: null;
}

function require_admin(): void
{
	if (!is_installed()) {
		redirect('../install.php');
	}

	if (!current_admin()) {
		flash('error', 'Please login to continue.');
		redirect('../login.php');
	}
}

function sanitize_pixel_key(string $pixelKey): string
{
	$pixelKey = trim($pixelKey);
	if ($pixelKey === '') {
		return '';
	}

	$pixelKey = preg_replace('/\s+/', '_', $pixelKey);
	if (function_exists('mb_strtolower')) {
		$pixelKey = mb_strtolower($pixelKey, 'UTF-8');
	} else {
		$pixelKey = strtolower($pixelKey);
	}

	$pixelKey = preg_replace('/[^a-z0-9_]/', '', $pixelKey);
	$pixelKey = preg_replace('/_+/', '_', $pixelKey);
	$pixelKey = trim($pixelKey, '_');

	return $pixelKey;
}

function create_pixel_if_missing(string $pixelKey, ?int $createdBy = null): int
{
	$pixelKey = sanitize_pixel_key($pixelKey);
	if ($pixelKey === '') {
		throw new InvalidArgumentException('Pixel key is required.');
	}

	$select = db()->prepare('SELECT id FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
	$select->execute(['pixel_key' => $pixelKey]);
	$row = $select->fetch();

	if ($row) {
		return (int) $row['id'];
	}

	$insert = db()->prepare(
		'INSERT INTO pd_pixels (pixel_key, label, created_by, created_at, updated_at, total_hits)
		 VALUES (:pixel_key, :label, :created_by, NOW(), NOW(), 0)'
	);
	$insert->execute([
		'pixel_key' => $pixelKey,
		'label' => $pixelKey,
		'created_by' => $createdBy,
	]);

	return (int) db()->lastInsertId();
}

function table_exists(PDO $pdo, string $table): bool
{
	$stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name');
	$stmt->execute(['table_name' => $table]);
	$row = $stmt->fetch();
	return (int) ($row['total'] ?? 0) > 0;
}

function column_exists(PDO $pdo, string $table, string $column): bool
{
	$stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND COLUMN_NAME = :column_name');
	$stmt->execute([
		'table_name' => $table,
		'column_name' => $column,
	]);
	$row = $stmt->fetch();
	return (int) ($row['total'] ?? 0) > 0;
}

function index_exists(PDO $pdo, string $table, string $index): bool
{
	$stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND INDEX_NAME = :index_name');
	$stmt->execute([
		'table_name' => $table,
		'index_name' => $index,
	]);
	$row = $stmt->fetch();
	return (int) ($row['total'] ?? 0) > 0;
}

function run_schema_migrations(PDO $pdo): array
{
	$applied = [];

	if (!table_exists($pdo, 'pd_admin_users')) {
		$pdo->exec(
			'CREATE TABLE pd_admin_users (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				username VARCHAR(100) NOT NULL UNIQUE,
				password_hash VARCHAR(255) NOT NULL,
				created_at DATETIME NOT NULL,
				last_login_at DATETIME NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_admin_users';
	}

	if (!table_exists($pdo, 'pd_pixels')) {
		$pdo->exec(
			'CREATE TABLE pd_pixels (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				pixel_key VARCHAR(191) NOT NULL UNIQUE,
				label VARCHAR(191) NOT NULL,
				created_by INT UNSIGNED NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				total_hits INT UNSIGNED NOT NULL DEFAULT 0,
				INDEX idx_pixel_key (pixel_key)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_pixels';
	}

	if (!table_exists($pdo, 'pd_pixel_hits')) {
		$pdo->exec(
			'CREATE TABLE pd_pixel_hits (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				pixel_id INT UNSIGNED NOT NULL,
				pixel_key VARCHAR(191) NOT NULL,
				hit_at DATETIME NOT NULL,
				ip_address VARCHAR(45) NOT NULL,
				user_agent TEXT NULL,
				referrer TEXT NULL,
				request_uri TEXT NULL,
				query_string TEXT NULL,
				accept_language VARCHAR(255) NULL,
				remote_host VARCHAR(255) NULL,
				INDEX idx_pixel_id (pixel_id),
				INDEX idx_pixel_key (pixel_key),
				INDEX idx_hit_at (hit_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_pixel_hits';
	}

	if (!table_exists($pdo, 'pd_trigger_actions')) {
		$pdo->exec(
			'CREATE TABLE pd_trigger_actions (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				trigger_id VARCHAR(191) NOT NULL UNIQUE,
				name VARCHAR(191) NOT NULL,
				webhook_url TEXT NOT NULL,
				payload_template TEXT NULL,
				is_active TINYINT(1) NOT NULL DEFAULT 1,
				is_default TINYINT(1) NOT NULL DEFAULT 0,
				created_by INT UNSIGNED NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				INDEX idx_trigger_id (trigger_id),
				INDEX idx_is_active (is_active),
				INDEX idx_is_default (is_default)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_trigger_actions';
	}

	if (!table_exists($pdo, 'pd_pixel_trigger_assignments')) {
		$pdo->exec(
			'CREATE TABLE pd_pixel_trigger_assignments (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				pixel_key VARCHAR(191) NOT NULL,
				trigger_action_id INT UNSIGNED NOT NULL,
				created_at DATETIME NOT NULL,
				UNIQUE KEY uniq_pixel_trigger (pixel_key, trigger_action_id),
				INDEX idx_pixel_key (pixel_key),
				INDEX idx_trigger_action_id (trigger_action_id)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_pixel_trigger_assignments';
	}

	$pixelColumns = [
		'label' => 'ALTER TABLE pd_pixels ADD COLUMN label VARCHAR(191) NOT NULL DEFAULT "" AFTER pixel_key',
		'created_by' => 'ALTER TABLE pd_pixels ADD COLUMN created_by INT UNSIGNED NULL AFTER label',
		'created_at' => 'ALTER TABLE pd_pixels ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_by',
		'updated_at' => 'ALTER TABLE pd_pixels ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
		'total_hits' => 'ALTER TABLE pd_pixels ADD COLUMN total_hits INT UNSIGNED NOT NULL DEFAULT 0 AFTER updated_at',
	];

	foreach ($pixelColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_pixels', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_pixels.' . $column;
		}
	}

	$hitColumns = [
		'pixel_id' => 'ALTER TABLE pd_pixel_hits ADD COLUMN pixel_id INT UNSIGNED NOT NULL AFTER id',
		'pixel_key' => 'ALTER TABLE pd_pixel_hits ADD COLUMN pixel_key VARCHAR(191) NOT NULL AFTER pixel_id',
		'hit_at' => 'ALTER TABLE pd_pixel_hits ADD COLUMN hit_at DATETIME NOT NULL AFTER pixel_key',
		'ip_address' => 'ALTER TABLE pd_pixel_hits ADD COLUMN ip_address VARCHAR(45) NOT NULL AFTER hit_at',
		'user_agent' => 'ALTER TABLE pd_pixel_hits ADD COLUMN user_agent TEXT NULL AFTER ip_address',
		'referrer' => 'ALTER TABLE pd_pixel_hits ADD COLUMN referrer TEXT NULL AFTER user_agent',
		'request_uri' => 'ALTER TABLE pd_pixel_hits ADD COLUMN request_uri TEXT NULL AFTER referrer',
		'query_string' => 'ALTER TABLE pd_pixel_hits ADD COLUMN query_string TEXT NULL AFTER request_uri',
		'accept_language' => 'ALTER TABLE pd_pixel_hits ADD COLUMN accept_language VARCHAR(255) NULL AFTER query_string',
		'remote_host' => 'ALTER TABLE pd_pixel_hits ADD COLUMN remote_host VARCHAR(255) NULL AFTER accept_language',
	];

	foreach ($hitColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_pixel_hits', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_pixel_hits.' . $column;
		}
	}

	$adminColumns = [
		'last_login_at' => 'ALTER TABLE pd_admin_users ADD COLUMN last_login_at DATETIME NULL AFTER created_at',
	];

	foreach ($adminColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_admin_users', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_admin_users.' . $column;
		}
	}

	$triggerColumns = [
		'trigger_id' => 'ALTER TABLE pd_trigger_actions ADD COLUMN trigger_id VARCHAR(191) NOT NULL AFTER id',
		'name' => 'ALTER TABLE pd_trigger_actions ADD COLUMN name VARCHAR(191) NOT NULL AFTER trigger_id',
		'webhook_url' => 'ALTER TABLE pd_trigger_actions ADD COLUMN webhook_url TEXT NOT NULL AFTER name',
		'payload_template' => 'ALTER TABLE pd_trigger_actions ADD COLUMN payload_template TEXT NULL AFTER webhook_url',
		'is_active' => 'ALTER TABLE pd_trigger_actions ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER payload_template',
		'is_default' => 'ALTER TABLE pd_trigger_actions ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active',
		'created_by' => 'ALTER TABLE pd_trigger_actions ADD COLUMN created_by INT UNSIGNED NULL AFTER is_default',
		'created_at' => 'ALTER TABLE pd_trigger_actions ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_by',
		'updated_at' => 'ALTER TABLE pd_trigger_actions ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
	];

	foreach ($triggerColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_trigger_actions', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_trigger_actions.' . $column;
		}
	}

	$assignmentColumns = [
		'pixel_key' => 'ALTER TABLE pd_pixel_trigger_assignments ADD COLUMN pixel_key VARCHAR(191) NOT NULL AFTER id',
		'trigger_action_id' => 'ALTER TABLE pd_pixel_trigger_assignments ADD COLUMN trigger_action_id INT UNSIGNED NOT NULL AFTER pixel_key',
		'created_at' => 'ALTER TABLE pd_pixel_trigger_assignments ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER trigger_action_id',
	];

	foreach ($assignmentColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_pixel_trigger_assignments', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_pixel_trigger_assignments.' . $column;
		}
	}

	$indexes = [
		['table' => 'pd_pixels', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixels (pixel_key)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_id', 'sql' => 'CREATE INDEX idx_pixel_id ON pd_pixel_hits (pixel_id)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixel_hits (pixel_key)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_hit_at', 'sql' => 'CREATE INDEX idx_hit_at ON pd_pixel_hits (hit_at)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_trigger_id', 'sql' => 'CREATE INDEX idx_trigger_id ON pd_trigger_actions (trigger_id)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_is_active', 'sql' => 'CREATE INDEX idx_is_active ON pd_trigger_actions (is_active)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_is_default', 'sql' => 'CREATE INDEX idx_is_default ON pd_trigger_actions (is_default)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixel_trigger_assignments (pixel_key)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'idx_trigger_action_id', 'sql' => 'CREATE INDEX idx_trigger_action_id ON pd_pixel_trigger_assignments (trigger_action_id)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'uniq_pixel_trigger', 'sql' => 'CREATE UNIQUE INDEX uniq_pixel_trigger ON pd_pixel_trigger_assignments (pixel_key, trigger_action_id)'],
	];

	foreach ($indexes as $indexDef) {
		if (!index_exists($pdo, $indexDef['table'], $indexDef['name'])) {
			$pdo->exec($indexDef['sql']);
			$applied[] = 'Created index ' . $indexDef['table'] . '.' . $indexDef['name'];
		}
	}

	return $applied;
}

function normalize_trigger_id(string $triggerId): string
{
	return trim($triggerId);
}

function get_active_triggers_for_pixel(?string $explicitTriggerId = null): array
{
	if ($explicitTriggerId === null || $explicitTriggerId === '') {
		return [];
	}

	$explicitStmt = db()->prepare(
		'SELECT id, trigger_id, name, webhook_url, payload_template
		 FROM pd_trigger_actions
		 WHERE trigger_id = :trigger_id AND is_active = 1
		 LIMIT 1'
	);
	$explicitStmt->execute(['trigger_id' => $explicitTriggerId]);
	$explicitAction = $explicitStmt->fetch();

	if (!$explicitAction) {
		return [];
	}

	return [$explicitAction];
}

function render_trigger_payload_template(?string $template, array $context): array
{
	if ($template === null || trim($template) === '') {
		return $context;
	}

	$rendered = $template;
	foreach ($context as $key => $value) {
		$rendered = str_replace('{{' . $key . '}}', (string) $value, $rendered);
	}

	$decoded = json_decode($rendered, true);
	if (is_array($decoded)) {
		return $decoded;
	}

	return [
		'message' => $rendered,
		'context' => $context,
	];
}

function send_webhook_json(string $url, array $payload): bool
{
	try {
		if (trim($url) === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
			return false;
		}

		$body = json_encode($payload, JSON_UNESCAPED_SLASHES);
		if (!is_string($body)) {
			return false;
		}

		if (function_exists('curl_init')) {
			$ch = curl_init($url);
			if ($ch === false) {
				return false;
			}

			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
				'Content-Type: application/json',
				'Content-Length: ' . strlen($body),
			]);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
			curl_setopt($ch, CURLOPT_TIMEOUT, 2);
			curl_exec($ch);
			$httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);

			return $httpCode >= 200 && $httpCode < 300;
		}

		$context = stream_context_create([
			'http' => [
				'method' => 'POST',
				'header' => "Content-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\n",
				'content' => $body,
				'timeout' => 2,
				'ignore_errors' => true,
			],
		]);

		$result = @file_get_contents($url, false, $context);
		return $result !== false;
	} catch (Throwable $e) {
		return false;
	}
}

function fire_pixel_triggers(string $pixelKey, int $pixelId, int $hitId, array $hitData, ?string $explicitTriggerId = null): void
{
	try {
		$triggerId = $explicitTriggerId !== null ? normalize_trigger_id($explicitTriggerId) : null;
		$actions = get_active_triggers_for_pixel($triggerId);
		if (!$actions) {
			return;
		}

		$totalHitsStmt = db()->prepare('SELECT total_hits FROM pd_pixels WHERE id = :id LIMIT 1');
		$totalHitsStmt->execute(['id' => $pixelId]);
		$totalHits = (int) ($totalHitsStmt->fetch()['total_hits'] ?? 0);

		$context = [
			'event' => 'pixel_loaded',
			'pixel_id' => $pixelKey,
			'pixel_db_id' => $pixelId,
			'hit_id' => $hitId,
			'hits' => $totalHits,
			'trigger_id' => $triggerId ?? '',
			'hit_at' => (string) ($hitData['hit_at'] ?? date('Y-m-d H:i:s')),
			'ip_address' => (string) ($hitData['ip_address'] ?? ''),
			'user_agent' => (string) ($hitData['user_agent'] ?? ''),
			'referrer' => (string) ($hitData['referrer'] ?? ''),
			'request_uri' => (string) ($hitData['request_uri'] ?? ''),
			'query_string' => (string) ($hitData['query_string'] ?? ''),
			'accept_language' => (string) ($hitData['accept_language'] ?? ''),
			'remote_host' => (string) ($hitData['remote_host'] ?? ''),
		];

		foreach ($actions as $action) {
			try {
				$payload = render_trigger_payload_template((string) ($action['payload_template'] ?? ''), $context);
				$payload['_trigger'] = [
					'id' => (string) $action['trigger_id'],
					'name' => (string) $action['name'],
				];
				send_webhook_json((string) $action['webhook_url'], $payload);
			} catch (Throwable $e) {
			}
		}
	} catch (Throwable $e) {
	}
}

function render_header(string $title): void
{
	$appName = app_config()['app']['name'] ?? 'Pixel Dust';
	echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
	echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
	echo '<title>' . e($title) . ' - ' . e($appName) . '</title>';
	echo '<style>
		body{font-family:Arial,sans-serif;background:#f7f7f7;margin:0;padding:0;color:#1e1e1e}
		.container{max-width:1040px;margin:24px auto;padding:0 16px}
		.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:16px}
		h1,h2,h3{margin:0 0 12px}
		p{margin:0 0 10px}
		table{width:100%;border-collapse:collapse}
		th,td{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}
		th{background:#f2f2f2}
		.muted{color:#666;font-size:0.9rem}
		.error{background:#ffeaea;color:#7f1d1d;padding:10px;border-radius:6px;margin-bottom:12px}
		.success{background:#e9f8ea;color:#14532d;padding:10px;border-radius:6px;margin-bottom:12px}
		input,select{padding:8px;border:1px solid #bbb;border-radius:4px;width:100%;box-sizing:border-box}
		button{padding:8px 12px;border:0;border-radius:4px;background:#1f4ea5;color:#fff;cursor:pointer}
		a{color:#1f4ea5;text-decoration:none}
		.nav-btn{display:inline-block;padding:8px 12px;border:1px solid #1f4ea5;border-radius:4px;background:#f0f5ff;color:#1f4ea5;font-size:0.92rem;line-height:1.2}
		.nav-btn:hover{background:#e3edff}
		.nav-btn.logout{border-color:#8b1e1e;background:#fff1f1;color:#8b1e1e}
		.nav-btn.logout:hover{background:#ffe6e6}
		.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
		.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
		.spaced{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
	</style>';
	echo '</head><body><div class="container">';
}

function render_footer(): void
{
	echo '</div></body></html>';
}
