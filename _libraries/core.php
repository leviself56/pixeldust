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

	try {
		$pdo->exec("SET time_zone = '+00:00'");
	} catch (Throwable $e) {
	}

	return $pdo;
}

function app_timezone_name(): string
{
	return (string) (app_config()['app']['timezone'] ?? 'UTC');
}

function app_timezone_object(): DateTimeZone
{
	try {
		return new DateTimeZone(app_timezone_name());
	} catch (Throwable $e) {
		return new DateTimeZone('UTC');
	}
}

function parse_db_datetime_utc(?string $value): ?DateTimeImmutable
{
	if ($value === null || trim($value) === '') {
		return null;
	}

	$value = trim($value);
	$dateTime = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $value, new DateTimeZone('UTC'));
	if ($dateTime instanceof DateTimeImmutable) {
		return $dateTime;
	}

	try {
		return new DateTimeImmutable($value, new DateTimeZone('UTC'));
	} catch (Throwable $e) {
		return null;
	}
}

function format_db_datetime(?string $value, string $format = 'Y-m-d H:i:s', string $empty = '-'): string
{
	$dateTimeUtc = parse_db_datetime_utc($value);
	if (!$dateTimeUtc) {
		return $empty;
	}

	return $dateTimeUtc->setTimezone(app_timezone_object())->format($format);
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

function fetch_ip_operator_tags(array $ipAddresses): array
{
	$normalized = [];
	foreach ($ipAddresses as $ipAddress) {
		$ip = trim((string) $ipAddress);
		if ($ip === '' || strlen($ip) > 45 || filter_var($ip, FILTER_VALIDATE_IP) === false) {
			continue;
		}
		$normalized[$ip] = true;
	}

	$ips = array_keys($normalized);
	if (!$ips) {
		return [];
	}

	$status = analytics_table_status();
	if (!(bool) ($status['ip_enrichment'] ?? false)) {
		return [];
	}

	$placeholders = implode(', ', array_fill(0, count($ips), '?'));
	try {
		$stmt = db()->prepare(
			"SELECT ip_address, operator_tag
			 FROM pd_ip_enrichment
			 WHERE ip_address IN ($placeholders)
			   AND operator_tag IS NOT NULL
			   AND TRIM(operator_tag) <> ''"
		);
		$stmt->execute($ips);
		$rows = $stmt->fetchAll();
	} catch (Throwable $e) {
		return [];
	}

	$tags = [];
	foreach ($rows as $row) {
		$ip = trim((string) ($row['ip_address'] ?? ''));
		$tag = trim((string) ($row['operator_tag'] ?? ''));
		if ($ip === '' || $tag === '') {
			continue;
		}
		$tags[$ip] = $tag;
	}

	return $tags;
}

function format_ip_with_operator_tag(string $ipAddress, ?string $operatorTag): string
{
	$ip = trim($ipAddress);
	$tag = trim((string) $operatorTag);
	if ($ip === '') {
		return '';
	}

	if ($tag === '') {
		return $ip;
	}

	return $ip . ' (' . $tag . ')';
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

function sanitize_redirect_key(string $redirectKey): string
{
	return sanitize_pixel_key($redirectKey);
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

	if (!table_exists($pdo, 'pd_redirect_links')) {
		$pdo->exec(
			'CREATE TABLE pd_redirect_links (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				redirect_key VARCHAR(191) NOT NULL UNIQUE,
				destination_url TEXT NOT NULL,
				is_active TINYINT(1) NOT NULL DEFAULT 1,
				created_by INT UNSIGNED NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				total_hits INT UNSIGNED NOT NULL DEFAULT 0,
				INDEX idx_redirect_key (redirect_key),
				INDEX idx_is_active (is_active)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_redirect_links';
	}

	if (!table_exists($pdo, 'pd_redirect_hits')) {
		$pdo->exec(
			'CREATE TABLE pd_redirect_hits (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				redirect_id INT UNSIGNED NOT NULL,
				redirect_key VARCHAR(191) NOT NULL,
				hit_at DATETIME NOT NULL,
				ip_address VARCHAR(45) NOT NULL,
				user_agent TEXT NULL,
				referrer TEXT NULL,
				request_uri TEXT NULL,
				query_string TEXT NULL,
				accept_language VARCHAR(255) NULL,
				remote_host VARCHAR(255) NULL,
				trigger_id_used VARCHAR(191) NULL,
				destination_url_at_hit TEXT NULL,
				INDEX idx_redirect_id (redirect_id),
				INDEX idx_redirect_key (redirect_key),
				INDEX idx_hit_at (hit_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_redirect_hits';
	}

	if (!table_exists($pdo, 'pd_redirect_hit_classification')) {
		$pdo->exec(
			'CREATE TABLE pd_redirect_hit_classification (
				hit_id BIGINT UNSIGNED PRIMARY KEY,
				redirect_id INT UNSIGNED NOT NULL,
				redirect_key VARCHAR(191) NOT NULL,
				ip_address VARCHAR(45) NOT NULL,
				email_client_guess VARCHAR(50) NOT NULL DEFAULT "unknown",
				email_client_confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000,
				traffic_type VARCHAR(30) NOT NULL DEFAULT "unknown",
				isp_guess VARCHAR(255) NULL,
				isp_source VARCHAR(30) NOT NULL DEFAULT "unknown",
				classified_at DATETIME NOT NULL,
				INDEX idx_redirect_time (redirect_id, classified_at),
				INDEX idx_redirect_ip (redirect_id, ip_address),
				INDEX idx_email_client (email_client_guess),
				INDEX idx_traffic_type (traffic_type)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_redirect_hit_classification';
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

	if (!table_exists($pdo, 'pd_ip_enrichment')) {
		$pdo->exec(
			'CREATE TABLE pd_ip_enrichment (
				ip_address VARCHAR(45) PRIMARY KEY,
				operator_tag VARCHAR(191) NULL,
				country_code CHAR(2) NULL,
				region VARCHAR(120) NULL,
				city VARCHAR(120) NULL,
				latitude DECIMAL(9,6) NULL,
				longitude DECIMAL(9,6) NULL,
				asn VARCHAR(20) NULL,
				asn_org VARCHAR(255) NULL,
				isp_name VARCHAR(255) NULL,
				reverse_host VARCHAR(255) NULL,
				reverse_host_updated_at DATETIME NULL,
				is_proxy TINYINT(1) NOT NULL DEFAULT 0,
				is_hosting TINYINT(1) NOT NULL DEFAULT 0,
				source VARCHAR(50) NOT NULL DEFAULT "unresolved",
				confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000,
				updated_at DATETIME NOT NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_ip_enrichment';
	}

	if (!table_exists($pdo, 'pd_hit_classification')) {
		$pdo->exec(
			'CREATE TABLE pd_hit_classification (
				hit_id BIGINT UNSIGNED PRIMARY KEY,
				pixel_id INT UNSIGNED NOT NULL,
				pixel_key VARCHAR(191) NOT NULL,
				ip_address VARCHAR(45) NOT NULL,
				email_client_guess VARCHAR(50) NOT NULL DEFAULT "unknown",
				email_client_confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000,
				traffic_type VARCHAR(30) NOT NULL DEFAULT "unknown",
				isp_guess VARCHAR(255) NULL,
				isp_source VARCHAR(30) NOT NULL DEFAULT "unknown",
				classified_at DATETIME NOT NULL,
				INDEX idx_pixel_time (pixel_id, classified_at),
				INDEX idx_pixel_ip (pixel_id, ip_address),
				INDEX idx_email_client (email_client_guess),
				INDEX idx_traffic_type (traffic_type)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_hit_classification';
	}

	if (!table_exists($pdo, 'pd_ip_enrichment_queue')) {
		$pdo->exec(
			'CREATE TABLE pd_ip_enrichment_queue (
				ip_address VARCHAR(45) PRIMARY KEY,
				first_seen_at DATETIME NOT NULL,
				last_seen_at DATETIME NOT NULL,
				next_attempt_at DATETIME NOT NULL,
				attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
				last_error VARCHAR(255) NULL,
				processed_at DATETIME NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_ip_enrichment_queue';
	}

	if (!table_exists($pdo, 'pd_traffic_fingerprint_library')) {
		$pdo->exec(
			'CREATE TABLE pd_traffic_fingerprint_library (
				fingerprint_key CHAR(40) PRIMARY KEY,
				source_type VARCHAR(20) NOT NULL,
				endpoint_path VARCHAR(255) NOT NULL,
				user_agent_hash CHAR(40) NOT NULL,
				user_agent_sample VARCHAR(255) NULL,
				hit_count INT UNSIGNED NOT NULL DEFAULT 0,
				distinct_ip_count INT UNSIGNED NOT NULL DEFAULT 0,
				last_ip_address VARCHAR(45) NULL,
				last_seen_at DATETIME NOT NULL,
				avg_interval_seconds DECIMAL(10,3) NULL,
				min_interval_seconds INT UNSIGNED NULL,
				classification VARCHAR(20) NOT NULL DEFAULT "unknown",
				confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000,
				updated_at DATETIME NOT NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_traffic_fingerprint_library';
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

	$redirectLinkColumns = [
		'redirect_key' => 'ALTER TABLE pd_redirect_links ADD COLUMN redirect_key VARCHAR(191) NOT NULL AFTER id',
		'destination_url' => 'ALTER TABLE pd_redirect_links ADD COLUMN destination_url TEXT NOT NULL AFTER redirect_key',
		'is_active' => 'ALTER TABLE pd_redirect_links ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER destination_url',
		'created_by' => 'ALTER TABLE pd_redirect_links ADD COLUMN created_by INT UNSIGNED NULL AFTER is_active',
		'created_at' => 'ALTER TABLE pd_redirect_links ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_by',
		'updated_at' => 'ALTER TABLE pd_redirect_links ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
		'total_hits' => 'ALTER TABLE pd_redirect_links ADD COLUMN total_hits INT UNSIGNED NOT NULL DEFAULT 0 AFTER updated_at',
	];

	foreach ($redirectLinkColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_redirect_links', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_redirect_links.' . $column;
		}
	}

	$redirectHitColumns = [
		'redirect_id' => 'ALTER TABLE pd_redirect_hits ADD COLUMN redirect_id INT UNSIGNED NOT NULL AFTER id',
		'redirect_key' => 'ALTER TABLE pd_redirect_hits ADD COLUMN redirect_key VARCHAR(191) NOT NULL AFTER redirect_id',
		'hit_at' => 'ALTER TABLE pd_redirect_hits ADD COLUMN hit_at DATETIME NOT NULL AFTER redirect_key',
		'ip_address' => 'ALTER TABLE pd_redirect_hits ADD COLUMN ip_address VARCHAR(45) NOT NULL AFTER hit_at',
		'user_agent' => 'ALTER TABLE pd_redirect_hits ADD COLUMN user_agent TEXT NULL AFTER ip_address',
		'referrer' => 'ALTER TABLE pd_redirect_hits ADD COLUMN referrer TEXT NULL AFTER user_agent',
		'request_uri' => 'ALTER TABLE pd_redirect_hits ADD COLUMN request_uri TEXT NULL AFTER referrer',
		'query_string' => 'ALTER TABLE pd_redirect_hits ADD COLUMN query_string TEXT NULL AFTER request_uri',
		'accept_language' => 'ALTER TABLE pd_redirect_hits ADD COLUMN accept_language VARCHAR(255) NULL AFTER query_string',
		'remote_host' => 'ALTER TABLE pd_redirect_hits ADD COLUMN remote_host VARCHAR(255) NULL AFTER accept_language',
		'trigger_id_used' => 'ALTER TABLE pd_redirect_hits ADD COLUMN trigger_id_used VARCHAR(191) NULL AFTER remote_host',
		'destination_url_at_hit' => 'ALTER TABLE pd_redirect_hits ADD COLUMN destination_url_at_hit TEXT NULL AFTER trigger_id_used',
	];

	foreach ($redirectHitColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_redirect_hits', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_redirect_hits.' . $column;
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

	$ipEnrichmentColumns = [
		'operator_tag' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN operator_tag VARCHAR(191) NULL AFTER ip_address',
		'country_code' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN country_code CHAR(2) NULL AFTER ip_address',
		'region' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN region VARCHAR(120) NULL AFTER country_code',
		'city' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN city VARCHAR(120) NULL AFTER region',
		'latitude' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN latitude DECIMAL(9,6) NULL AFTER city',
		'longitude' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN longitude DECIMAL(9,6) NULL AFTER latitude',
		'asn' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN asn VARCHAR(20) NULL AFTER longitude',
		'asn_org' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN asn_org VARCHAR(255) NULL AFTER asn',
		'isp_name' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN isp_name VARCHAR(255) NULL AFTER asn_org',
		'reverse_host' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN reverse_host VARCHAR(255) NULL AFTER isp_name',
		'reverse_host_updated_at' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN reverse_host_updated_at DATETIME NULL AFTER reverse_host',
		'is_proxy' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN is_proxy TINYINT(1) NOT NULL DEFAULT 0 AFTER isp_name',
		'is_hosting' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN is_hosting TINYINT(1) NOT NULL DEFAULT 0 AFTER is_proxy',
		'source' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN source VARCHAR(50) NOT NULL DEFAULT "unresolved" AFTER is_hosting',
		'confidence' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000 AFTER source',
		'updated_at' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER confidence',
	];

	foreach ($ipEnrichmentColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_ip_enrichment', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_ip_enrichment.' . $column;
		}
	}

	$hitClassificationColumns = [
		'pixel_id' => 'ALTER TABLE pd_hit_classification ADD COLUMN pixel_id INT UNSIGNED NOT NULL AFTER hit_id',
		'pixel_key' => 'ALTER TABLE pd_hit_classification ADD COLUMN pixel_key VARCHAR(191) NOT NULL AFTER pixel_id',
		'ip_address' => 'ALTER TABLE pd_hit_classification ADD COLUMN ip_address VARCHAR(45) NOT NULL AFTER pixel_key',
		'email_client_guess' => 'ALTER TABLE pd_hit_classification ADD COLUMN email_client_guess VARCHAR(50) NOT NULL DEFAULT "unknown" AFTER ip_address',
		'email_client_confidence' => 'ALTER TABLE pd_hit_classification ADD COLUMN email_client_confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000 AFTER email_client_guess',
		'traffic_type' => 'ALTER TABLE pd_hit_classification ADD COLUMN traffic_type VARCHAR(30) NOT NULL DEFAULT "unknown" AFTER email_client_confidence',
		'isp_guess' => 'ALTER TABLE pd_hit_classification ADD COLUMN isp_guess VARCHAR(255) NULL AFTER traffic_type',
		'isp_source' => 'ALTER TABLE pd_hit_classification ADD COLUMN isp_source VARCHAR(30) NOT NULL DEFAULT "unknown" AFTER isp_guess',
		'classified_at' => 'ALTER TABLE pd_hit_classification ADD COLUMN classified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER isp_source',
	];

	foreach ($hitClassificationColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_hit_classification', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_hit_classification.' . $column;
		}
	}

	$redirectClassificationColumns = [
		'redirect_id' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN redirect_id INT UNSIGNED NOT NULL AFTER hit_id',
		'redirect_key' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN redirect_key VARCHAR(191) NOT NULL AFTER redirect_id',
		'ip_address' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN ip_address VARCHAR(45) NOT NULL AFTER redirect_key',
		'email_client_guess' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN email_client_guess VARCHAR(50) NOT NULL DEFAULT "unknown" AFTER ip_address',
		'email_client_confidence' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN email_client_confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000 AFTER email_client_guess',
		'traffic_type' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN traffic_type VARCHAR(30) NOT NULL DEFAULT "unknown" AFTER email_client_confidence',
		'isp_guess' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN isp_guess VARCHAR(255) NULL AFTER traffic_type',
		'isp_source' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN isp_source VARCHAR(30) NOT NULL DEFAULT "unknown" AFTER isp_guess',
		'classified_at' => 'ALTER TABLE pd_redirect_hit_classification ADD COLUMN classified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER isp_source',
	];

	foreach ($redirectClassificationColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_redirect_hit_classification', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_redirect_hit_classification.' . $column;
		}
	}

	$queueColumns = [
		'first_seen_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER ip_address',
		'last_seen_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER first_seen_at',
		'next_attempt_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER last_seen_at',
		'attempt_count' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN attempt_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER next_attempt_at',
		'last_error' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN last_error VARCHAR(255) NULL AFTER attempt_count',
		'processed_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN processed_at DATETIME NULL AFTER last_error',
		'created_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER processed_at',
		'updated_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
	];

	foreach ($queueColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_ip_enrichment_queue', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_ip_enrichment_queue.' . $column;
		}
	}

	$fingerprintColumns = [
		'source_type' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN source_type VARCHAR(20) NOT NULL DEFAULT "unknown" AFTER fingerprint_key',
		'endpoint_path' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN endpoint_path VARCHAR(255) NOT NULL DEFAULT "/" AFTER source_type',
		'user_agent_hash' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN user_agent_hash CHAR(40) NOT NULL AFTER endpoint_path',
		'user_agent_sample' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN user_agent_sample VARCHAR(255) NULL AFTER user_agent_hash',
		'hit_count' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN hit_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER user_agent_sample',
		'distinct_ip_count' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN distinct_ip_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER hit_count',
		'last_ip_address' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN last_ip_address VARCHAR(45) NULL AFTER distinct_ip_count',
		'last_seen_at' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER last_ip_address',
		'avg_interval_seconds' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN avg_interval_seconds DECIMAL(10,3) NULL AFTER last_seen_at',
		'min_interval_seconds' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN min_interval_seconds INT UNSIGNED NULL AFTER avg_interval_seconds',
		'classification' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN classification VARCHAR(20) NOT NULL DEFAULT "unknown" AFTER min_interval_seconds',
		'confidence' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000 AFTER classification',
		'updated_at' => 'ALTER TABLE pd_traffic_fingerprint_library ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER confidence',
	];

	foreach ($fingerprintColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_traffic_fingerprint_library', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_traffic_fingerprint_library.' . $column;
		}
	}

	$indexes = [
		['table' => 'pd_pixels', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixels (pixel_key)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_id', 'sql' => 'CREATE INDEX idx_pixel_id ON pd_pixel_hits (pixel_id)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixel_hits (pixel_key)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_hit_at', 'sql' => 'CREATE INDEX idx_hit_at ON pd_pixel_hits (hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_time', 'sql' => 'CREATE INDEX idx_pixel_time ON pd_pixel_hits (pixel_id, hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_ip_time', 'sql' => 'CREATE INDEX idx_pixel_ip_time ON pd_pixel_hits (pixel_id, ip_address, hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_ref_time', 'sql' => 'CREATE INDEX idx_pixel_ref_time ON pd_pixel_hits (pixel_id, referrer(191), hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_host_time', 'sql' => 'CREATE INDEX idx_pixel_host_time ON pd_pixel_hits (pixel_id, remote_host(191), hit_at)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_trigger_id', 'sql' => 'CREATE INDEX idx_trigger_id ON pd_trigger_actions (trigger_id)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_is_active', 'sql' => 'CREATE INDEX idx_is_active ON pd_trigger_actions (is_active)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_is_default', 'sql' => 'CREATE INDEX idx_is_default ON pd_trigger_actions (is_default)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixel_trigger_assignments (pixel_key)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'idx_trigger_action_id', 'sql' => 'CREATE INDEX idx_trigger_action_id ON pd_pixel_trigger_assignments (trigger_action_id)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'uniq_pixel_trigger', 'sql' => 'CREATE UNIQUE INDEX uniq_pixel_trigger ON pd_pixel_trigger_assignments (pixel_key, trigger_action_id)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_country', 'sql' => 'CREATE INDEX idx_country ON pd_ip_enrichment (country_code)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_asn', 'sql' => 'CREATE INDEX idx_asn ON pd_ip_enrichment (asn)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_isp', 'sql' => 'CREATE INDEX idx_isp ON pd_ip_enrichment (isp_name)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_reverse_host', 'sql' => 'CREATE INDEX idx_reverse_host ON pd_ip_enrichment (reverse_host)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_pixel_time', 'sql' => 'CREATE INDEX idx_pixel_time ON pd_hit_classification (pixel_id, classified_at)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_pixel_ip', 'sql' => 'CREATE INDEX idx_pixel_ip ON pd_hit_classification (pixel_id, ip_address)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_email_client', 'sql' => 'CREATE INDEX idx_email_client ON pd_hit_classification (email_client_guess)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_traffic_type', 'sql' => 'CREATE INDEX idx_traffic_type ON pd_hit_classification (traffic_type)'],
		['table' => 'pd_redirect_links', 'name' => 'idx_redirect_key', 'sql' => 'CREATE INDEX idx_redirect_key ON pd_redirect_links (redirect_key)'],
		['table' => 'pd_redirect_links', 'name' => 'idx_is_active', 'sql' => 'CREATE INDEX idx_is_active ON pd_redirect_links (is_active)'],
		['table' => 'pd_redirect_hits', 'name' => 'idx_redirect_id', 'sql' => 'CREATE INDEX idx_redirect_id ON pd_redirect_hits (redirect_id)'],
		['table' => 'pd_redirect_hits', 'name' => 'idx_redirect_key', 'sql' => 'CREATE INDEX idx_redirect_key ON pd_redirect_hits (redirect_key)'],
		['table' => 'pd_redirect_hits', 'name' => 'idx_hit_at', 'sql' => 'CREATE INDEX idx_hit_at ON pd_redirect_hits (hit_at)'],
		['table' => 'pd_redirect_hits', 'name' => 'idx_redirect_time', 'sql' => 'CREATE INDEX idx_redirect_time ON pd_redirect_hits (redirect_id, hit_at)'],
		['table' => 'pd_redirect_hits', 'name' => 'idx_redirect_ip_time', 'sql' => 'CREATE INDEX idx_redirect_ip_time ON pd_redirect_hits (redirect_id, ip_address, hit_at)'],
		['table' => 'pd_redirect_hit_classification', 'name' => 'idx_redirect_time', 'sql' => 'CREATE INDEX idx_redirect_time ON pd_redirect_hit_classification (redirect_id, classified_at)'],
		['table' => 'pd_redirect_hit_classification', 'name' => 'idx_redirect_ip', 'sql' => 'CREATE INDEX idx_redirect_ip ON pd_redirect_hit_classification (redirect_id, ip_address)'],
		['table' => 'pd_redirect_hit_classification', 'name' => 'idx_email_client', 'sql' => 'CREATE INDEX idx_email_client ON pd_redirect_hit_classification (email_client_guess)'],
		['table' => 'pd_redirect_hit_classification', 'name' => 'idx_traffic_type', 'sql' => 'CREATE INDEX idx_traffic_type ON pd_redirect_hit_classification (traffic_type)'],
		['table' => 'pd_ip_enrichment_queue', 'name' => 'idx_next_attempt', 'sql' => 'CREATE INDEX idx_next_attempt ON pd_ip_enrichment_queue (next_attempt_at)'],
		['table' => 'pd_ip_enrichment_queue', 'name' => 'idx_last_seen', 'sql' => 'CREATE INDEX idx_last_seen ON pd_ip_enrichment_queue (last_seen_at)'],
		['table' => 'pd_traffic_fingerprint_library', 'name' => 'idx_source_type', 'sql' => 'CREATE INDEX idx_source_type ON pd_traffic_fingerprint_library (source_type)'],
		['table' => 'pd_traffic_fingerprint_library', 'name' => 'idx_classification', 'sql' => 'CREATE INDEX idx_classification ON pd_traffic_fingerprint_library (classification)'],
		['table' => 'pd_traffic_fingerprint_library', 'name' => 'idx_last_seen', 'sql' => 'CREATE INDEX idx_last_seen ON pd_traffic_fingerprint_library (last_seen_at)'],
	];

	foreach ($indexes as $indexDef) {
		if (!index_exists($pdo, $indexDef['table'], $indexDef['name'])) {
			$pdo->exec($indexDef['sql']);
			$applied[] = 'Created index ' . $indexDef['table'] . '.' . $indexDef['name'];
		}
	}

	return $applied;
}

function analytics_table_status(): array
{
	static $status = null;

	if (is_array($status)) {
		return $status;
	}

	try {
		$pdo = db();
		$status = [
			'ip_enrichment' => table_exists($pdo, 'pd_ip_enrichment'),
			'hit_classification' => table_exists($pdo, 'pd_hit_classification'),
			'redirect_hit_classification' => table_exists($pdo, 'pd_redirect_hit_classification'),
			'ip_queue' => table_exists($pdo, 'pd_ip_enrichment_queue'),
			'traffic_fingerprints' => table_exists($pdo, 'pd_traffic_fingerprint_library'),
		];
	} catch (Throwable $e) {
		$status = [
			'ip_enrichment' => false,
			'hit_classification' => false,
			'redirect_hit_classification' => false,
			'ip_queue' => false,
			'traffic_fingerprints' => false,
		];
	}

	return $status;
}

function is_public_ip(string $ipAddress): bool
{
	return filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function normalize_referrer_domain(?string $referrer): string
{
	if ($referrer === null) {
		return '-';
	}

	$referrer = trim($referrer);
	if ($referrer === '') {
		return '-';
	}

	$host = parse_url($referrer, PHP_URL_HOST);
	if (!is_string($host) || trim($host) === '') {
		$clean = strtolower($referrer);
		$clean = preg_replace('/^[a-z]+:\/\//i', '', $clean);
		$parts = explode('/', $clean, 2);
		$host = $parts[0] ?? '';
	}

	$host = strtolower(trim((string) $host));
	return $host !== '' ? $host : '-';
}

function infer_isp_from_remote_host(?string $remoteHost): ?string
{
	if ($remoteHost === null) {
		return null;
	}

	$remoteHost = trim(strtolower($remoteHost));
	if ($remoteHost === '') {
		return null;
	}

	if (preg_match('/^[0-9]+(\.[0-9]+){3}$/', $remoteHost) === 1) {
		return null;
	}

	if (strpos($remoteHost, 'google-proxy-') === 0 || str_ends_with($remoteHost, '.google.com')) {
		return 'Google';
	}

	if (strpos($remoteHost, '.ycpi.') !== false && str_ends_with($remoteHost, '.yahoo.com')) {
		return 'Yahoo';
	}

	$parts = explode('.', $remoteHost);
	if (count($parts) >= 2) {
		return $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
	}

	return $remoteHost;
}

function normalize_reverse_host_result(string $ipAddress, ?string $resolved): ?string
{
	$resolved = trim((string) $resolved);
	if ($resolved === '') {
		return null;
	}

	$resolvedLower = strtolower($resolved);
	if ($resolvedLower === strtolower($ipAddress)) {
		return null;
	}

	if (preg_match('/^[0-9]+(\.[0-9]+){3}$/', $resolvedLower) === 1) {
		return null;
	}

	return substr($resolvedLower, 0, 255);
}

function resolve_reverse_host_for_ip(string $ipAddress): ?string
{
	$ipAddress = trim($ipAddress);
	if ($ipAddress === '' || !is_public_ip($ipAddress)) {
		return null;
	}

	$resolved = @gethostbyaddr($ipAddress);
	if (!is_string($resolved)) {
		return null;
	}

	return normalize_reverse_host_result($ipAddress, $resolved);
}

function ensure_reverse_host_for_ip(string $ipAddress, bool $allowLookup = false): ?string
{
	$status = analytics_table_status();
	if (!$status['ip_enrichment']) {
		return null;
	}

	$ipAddress = trim($ipAddress);
	if ($ipAddress === '') {
		return null;
	}

	try {
		$existingStmt = db()->prepare('SELECT reverse_host, reverse_host_updated_at FROM pd_ip_enrichment WHERE ip_address = :ip_address LIMIT 1');
		$existingStmt->execute(['ip_address' => $ipAddress]);
		$existing = $existingStmt->fetch();
		if ($existing && trim((string) ($existing['reverse_host'] ?? '')) !== '') {
			return (string) $existing['reverse_host'];
		}
	} catch (Throwable $e) {
		return null;
	}

	if (!$allowLookup) {
		return null;
	}

	$resolvedHost = resolve_reverse_host_for_ip($ipAddress);
	if ($resolvedHost === null) {
		return null;
	}

	try {
		$upsert = db()->prepare(
			'INSERT INTO pd_ip_enrichment (ip_address, reverse_host, reverse_host_updated_at, source, confidence, updated_at)
			 VALUES (:ip_address, :reverse_host, NOW(), "rdns", 0.500, NOW())
			 ON DUPLICATE KEY UPDATE
				reverse_host = VALUES(reverse_host),
				reverse_host_updated_at = NOW(),
				updated_at = NOW()'
		);
		$upsert->execute([
			'ip_address' => $ipAddress,
			'reverse_host' => $resolvedHost,
		]);
	} catch (Throwable $e) {
	}

	return $resolvedHost;
}

function backfill_remote_host_for_ip_hits(string $ipAddress, string $remoteHost, int $maxRowsPerTable = 250): int
{
	$ipAddress = trim($ipAddress);
	$remoteHost = trim($remoteHost);
	if ($ipAddress === '' || $remoteHost === '' || $maxRowsPerTable < 1) {
		return 0;
	}

	$updated = 0;
	$maxRowsPerTable = max(1, min(2000, $maxRowsPerTable));

	try {
		$pdo = db();
		if (table_exists($pdo, 'pd_pixel_hits')) {
			$updatePixel = db()->prepare(
				'UPDATE pd_pixel_hits
				 SET remote_host = :remote_host
				 WHERE ip_address = :ip_address
				   AND (remote_host IS NULL OR TRIM(remote_host) = \'\')
				 LIMIT :row_limit'
			);
			$updatePixel->bindValue(':remote_host', $remoteHost, PDO::PARAM_STR);
			$updatePixel->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
			$updatePixel->bindValue(':row_limit', $maxRowsPerTable, PDO::PARAM_INT);
			$updatePixel->execute();
			$updated += (int) $updatePixel->rowCount();
		}

		if (table_exists($pdo, 'pd_redirect_hits')) {
			$updateRedirect = db()->prepare(
				'UPDATE pd_redirect_hits
				 SET remote_host = :remote_host
				 WHERE ip_address = :ip_address
				   AND (remote_host IS NULL OR TRIM(remote_host) = \'\')
				 LIMIT :row_limit'
			);
			$updateRedirect->bindValue(':remote_host', $remoteHost, PDO::PARAM_STR);
			$updateRedirect->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
			$updateRedirect->bindValue(':row_limit', $maxRowsPerTable, PDO::PARAM_INT);
			$updateRedirect->execute();
			$updated += (int) $updateRedirect->rowCount();
		}
	} catch (Throwable $e) {
	}

	return $updated;
}

function infer_email_client(array $hit): array
{
	$userAgent = strtolower((string) ($hit['user_agent'] ?? ''));
	$referrer = strtolower((string) ($hit['referrer'] ?? ''));
	$remoteHost = strtolower((string) ($hit['remote_host'] ?? ''));

	if (
		strpos($userAgent, 'googleimageproxy') !== false ||
		strpos($remoteHost, 'google-proxy-') === 0 ||
		strpos($referrer, 'mobile-webview.gmail.com') !== false ||
		strpos($referrer, 'mail.google.com') !== false
	) {
		return ['client' => 'gmail', 'confidence' => 0.95];
	}

	if (
		strpos($userAgent, 'yahoomailproxy') !== false ||
		(strpos($remoteHost, '.ycpi.') !== false && str_ends_with($remoteHost, '.yahoo.com'))
	) {
		return ['client' => 'yahoo_mail', 'confidence' => 0.95];
	}

	if (
		strpos($referrer, 'outlook.live.com') !== false ||
		strpos($userAgent, 'oneoutlook/') !== false ||
		strpos($userAgent, 'ms-office') !== false
	) {
		return ['client' => 'outlook_family', 'confidence' => 0.9];
	}

	if (
		strpos($referrer, 'webmail.') !== false ||
		strpos($referrer, 'mail.') !== false ||
		strpos($referrer, 'neo.space') !== false ||
		strpos($referrer, 'titan.email') !== false
	) {
		return ['client' => 'other_webmail', 'confidence' => 0.7];
	}

	return ['client' => 'unknown', 'confidence' => 0.2];
}

function extract_request_path_from_uri(?string $requestUri): string
{
	$requestUri = trim((string) $requestUri);
	if ($requestUri === '') {
		return '/';
	}

	$path = parse_url($requestUri, PHP_URL_PATH);
	if (!is_string($path) || trim($path) === '') {
		return '/';
	}

	$path = '/' . ltrim(trim($path), '/');
	return strtolower($path);
}

function infer_source_type_from_request_uri(?string $requestUri): string
{
	$path = extract_request_path_from_uri($requestUri);
	$scriptName = strtolower((string) basename($path));
	if ($scriptName === 'pix.php') {
		return 'pixel';
	}
	if ($scriptName === 'link.php') {
		return 'redirect';
	}

	return 'unknown';
}

function traffic_fingerprint_key(string $sourceType, string $requestPath, string $userAgent): string
{
	$sourceType = strtolower(trim($sourceType));
	$requestPath = strtolower(trim($requestPath));
	$userAgent = strtolower(trim($userAgent));
	return sha1($sourceType . '|' . $requestPath . '|' . $userAgent);
}

function infer_traffic_classification_from_observation(string $userAgent, int $hitCount, int $distinctIpCount, ?float $avgIntervalSeconds, ?int $minIntervalSeconds): array
{
	$userAgent = strtolower(trim($userAgent));

	if ($userAgent !== '' && (strpos($userAgent, 'googleimageproxy') !== false || strpos($userAgent, 'yahoomailproxy') !== false || strpos($userAgent, 'oneoutlook/') !== false || strpos($userAgent, 'ms-office') !== false)) {
		return ['classification' => 'proxy', 'confidence' => 0.95];
	}

	if ($userAgent !== '' && (strpos($userAgent, 'bot') !== false || strpos($userAgent, 'crawler') !== false || strpos($userAgent, 'spider') !== false || strpos($userAgent, 'curl/') !== false || strpos($userAgent, 'wget/') !== false || strpos($userAgent, 'python-requests') !== false || strpos($userAgent, 'headless') !== false)) {
		return ['classification' => 'bot', 'confidence' => 0.95];
	}

	if ($hitCount >= 25 && $distinctIpCount <= 2 && $avgIntervalSeconds !== null && $avgIntervalSeconds <= 5.0) {
		return ['classification' => 'bot', 'confidence' => 0.85];
	}

	if ($hitCount >= 40 && $avgIntervalSeconds !== null && $avgIntervalSeconds <= 12.0 && $minIntervalSeconds !== null && $minIntervalSeconds <= 1) {
		return ['classification' => 'bot', 'confidence' => 0.80];
	}

	if ($hitCount >= 15 && $distinctIpCount >= 4 && $avgIntervalSeconds !== null && $avgIntervalSeconds <= 20.0) {
		return ['classification' => 'proxy', 'confidence' => 0.72];
	}

	return ['classification' => 'unknown', 'confidence' => 0.20];
}

function get_traffic_type_hint_from_fingerprint(array $hit): ?string
{
	static $cache = [];

	$status = analytics_table_status();
	if (!(bool) ($status['traffic_fingerprints'] ?? false)) {
		return null;
	}

	$requestUri = (string) ($hit['request_uri'] ?? '');
	$userAgent = (string) ($hit['user_agent'] ?? '');
	$sourceType = (string) ($hit['source_type'] ?? infer_source_type_from_request_uri($requestUri));
	$requestPath = extract_request_path_from_uri($requestUri);

	if ($sourceType === 'unknown' || trim($userAgent) === '') {
		return null;
	}

	$key = traffic_fingerprint_key($sourceType, $requestPath, $userAgent);
	if (array_key_exists($key, $cache)) {
		return $cache[$key];
	}

	try {
		$stmt = db()->prepare(
			'SELECT classification, confidence
			 FROM pd_traffic_fingerprint_library
			 WHERE fingerprint_key = :fingerprint_key
			 LIMIT 1'
		);
		$stmt->execute(['fingerprint_key' => $key]);
		$row = $stmt->fetch();
		if (!$row) {
			$cache[$key] = null;
			return null;
		}

		$classification = strtolower(trim((string) ($row['classification'] ?? '')));
		$confidence = (float) ($row['confidence'] ?? 0);
		if (($classification === 'bot' || $classification === 'proxy') && $confidence >= 0.7) {
			$cache[$key] = $classification;
			return $classification;
		}
	} catch (Throwable $e) {
	}

	$cache[$key] = null;
	return null;
}

function infer_traffic_type(array $hit, array $enrichment, string $emailClient): string
{
	$userAgent = strtolower((string) ($hit['user_agent'] ?? ''));
	$fingerprintHint = get_traffic_type_hint_from_fingerprint($hit);

	if ($fingerprintHint === 'bot') {
		return 'bot';
	}

	if ($emailClient === 'gmail' || $emailClient === 'yahoo_mail') {
		return 'proxy';
	}

	if ($fingerprintHint === 'proxy') {
		return 'proxy';
	}

	if (strpos($userAgent, 'bot') !== false || strpos($userAgent, 'crawler') !== false || strpos($userAgent, 'spider') !== false) {
		return 'bot';
	}

	if ((int) ($enrichment['is_proxy'] ?? 0) === 1) {
		return 'proxy';
	}

	if (trim((string) ($hit['user_agent'] ?? '')) === '') {
		return 'unknown';
	}

	return 'human';
}

function evaluate_ip_bot_tag_confidence(string $ipAddress): array
{
	$result = [
		'score' => 0,
		'total_hits' => 0,
		'bot_hits' => 0,
		'proxy_hits' => 0,
		'email_proxy_hits' => 0,
		'should_tag' => false,
	];

	$ipAddress = trim($ipAddress);
	if ($ipAddress === '' || filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
		return $result;
	}

	$status = analytics_table_status();
	$subQueries = [];
	$params = [];

	if ((bool) ($status['hit_classification'] ?? false)) {
		$subQueries[] =
			"SELECT traffic_type, email_client_guess
			 FROM pd_hit_classification
			 WHERE ip_address = :pixel_ip
			   AND classified_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
		$params['pixel_ip'] = $ipAddress;
	}

	if ((bool) ($status['redirect_hit_classification'] ?? false)) {
		$subQueries[] =
			"SELECT traffic_type, email_client_guess
			 FROM pd_redirect_hit_classification
			 WHERE ip_address = :redirect_ip
			   AND classified_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
		$params['redirect_ip'] = $ipAddress;
	}

	if (!$subQueries) {
		return $result;
	}

	$classificationUnionSql = implode(' UNION ALL ', $subQueries);

	try {
		$aggStmt = db()->prepare(
			"SELECT
				COUNT(*) AS total_hits,
				SUM(CASE WHEN traffic_type = 'bot' THEN 1 ELSE 0 END) AS bot_hits,
				SUM(CASE WHEN traffic_type = 'proxy' THEN 1 ELSE 0 END) AS proxy_hits,
				SUM(CASE WHEN email_client_guess IN ('gmail', 'yahoo_mail', 'outlook_family', 'other_webmail') THEN 1 ELSE 0 END) AS email_proxy_hits
			 FROM ($classificationUnionSql) classified"
		);
		$aggStmt->execute($params);
		$agg = (array) $aggStmt->fetch();
	} catch (Throwable $e) {
		return $result;
	}

	$totalHits = (int) ($agg['total_hits'] ?? 0);
	$botHits = (int) ($agg['bot_hits'] ?? 0);
	$proxyHits = (int) ($agg['proxy_hits'] ?? 0);
	$emailProxyHits = (int) ($agg['email_proxy_hits'] ?? 0);

	$result['total_hits'] = $totalHits;
	$result['bot_hits'] = $botHits;
	$result['proxy_hits'] = $proxyHits;
	$result['email_proxy_hits'] = $emailProxyHits;

	if ($totalHits < 12) {
		return $result;
	}

	$botRatio = $totalHits > 0 ? ($botHits / $totalHits) : 0.0;
	$proxyRatio = $totalHits > 0 ? ($proxyHits / $totalHits) : 0.0;
	$emailRatio = $totalHits > 0 ? ($emailProxyHits / $totalHits) : 0.0;

	$score = 0;
	if ($botRatio >= 0.95) {
		$score += 55;
	} elseif ($botRatio >= 0.90) {
		$score += 45;
	} elseif ($botRatio >= 0.85) {
		$score += 35;
	}

	if ($botHits >= 60) {
		$score += 25;
	} elseif ($botHits >= 30) {
		$score += 20;
	} elseif ($botHits >= 15) {
		$score += 12;
	}

	if ($proxyRatio <= 0.10) {
		$score += 12;
	} elseif ($proxyRatio <= 0.20) {
		$score += 8;
	} elseif ($proxyRatio <= 0.30) {
		$score += 4;
	}

	if ($emailRatio <= 0.03) {
		$score += 18;
	} elseif ($emailRatio <= 0.08) {
		$score += 10;
	} elseif ($emailRatio <= 0.12) {
		$score += 4;
	}

	$shouldTag =
		$score >= 80 &&
		$botHits >= 15 &&
		$botRatio >= 0.85 &&
		$emailProxyHits <= max(1, (int) floor($totalHits * 0.08));

	$result['score'] = $score;
	$result['should_tag'] = $shouldTag;

	return $result;
}

function auto_tag_ip_as_bot_if_confident(string $ipAddress): bool
{
	$ipAddress = trim($ipAddress);
	if ($ipAddress === '' || filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
		return false;
	}

	$status = analytics_table_status();
	if (!(bool) ($status['ip_enrichment'] ?? false)) {
		return false;
	}

	try {
		$currentStmt = db()->prepare('SELECT operator_tag FROM pd_ip_enrichment WHERE ip_address = :ip_address LIMIT 1');
		$currentStmt->execute(['ip_address' => $ipAddress]);
		$current = $currentStmt->fetch();
		$currentTag = strtolower(trim((string) ($current['operator_tag'] ?? '')));
		if ($currentTag !== '' && $currentTag !== 'bot') {
			return false;
		}
	} catch (Throwable $e) {
		return false;
	}

	$assessment = evaluate_ip_bot_tag_confidence($ipAddress);
	if (!(bool) ($assessment['should_tag'] ?? false)) {
		return false;
	}

	try {
		$tagStmt = db()->prepare(
			'INSERT INTO pd_ip_enrichment (ip_address, operator_tag, source, confidence, updated_at)
			 VALUES (:ip_address, "bot", "bot_auto", 0.980, NOW())
			 ON DUPLICATE KEY UPDATE
				operator_tag = CASE
					WHEN operator_tag IS NULL OR TRIM(operator_tag) = "" OR LOWER(TRIM(operator_tag)) = "bot"
					THEN "bot"
					ELSE operator_tag
				END,
				source = CASE
					WHEN operator_tag IS NULL OR TRIM(operator_tag) = "" OR LOWER(TRIM(operator_tag)) = "bot"
					THEN "bot_auto"
					ELSE source
				END,
				confidence = CASE
					WHEN operator_tag IS NULL OR TRIM(operator_tag) = "" OR LOWER(TRIM(operator_tag)) = "bot"
					THEN 0.980
					ELSE confidence
				END,
				updated_at = NOW()'
		);
		$tagStmt->execute(['ip_address' => $ipAddress]);
		return true;
	} catch (Throwable $e) {
		return false;
	}
}

function lookup_ip_enrichment_remote(string $ipAddress): array
{
	$default = [
		'ip_address' => $ipAddress,
		'operator_tag' => null,
		'country_code' => null,
		'region' => null,
		'city' => null,
		'latitude' => null,
		'longitude' => null,
		'asn' => null,
		'asn_org' => null,
		'isp_name' => null,
		'reverse_host' => null,
		'is_proxy' => 0,
		'is_hosting' => 0,
		'source' => 'unresolved',
		'confidence' => 0.0,
	];

	if (!is_public_ip($ipAddress)) {
		$default['source'] = 'private_or_reserved';
		return $default;
	}

	$fetchJson = static function (string $url): ?array {
		$response = false;

		if (function_exists('curl_init')) {
			$ch = curl_init($url);
			if ($ch !== false) {
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
				curl_setopt($ch, CURLOPT_TIMEOUT, 4);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
				curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
				$response = curl_exec($ch);
				curl_close($ch);
			}
		} else {
			$context = stream_context_create([
				'http' => [
					'timeout' => 4,
				],
			]);
			$response = @file_get_contents($url, false, $context);
		}

		if (!is_string($response) || trim($response) === '') {
			return null;
		}

		$decoded = json_decode($response, true);
		return is_array($decoded) ? $decoded : null;
	};

	$rdapFallback = static function () use ($ipAddress, $default, $fetchJson): array {
		$rdap = $fetchJson('https://rdap.org/ip/' . rawurlencode($ipAddress));
		if (!is_array($rdap)) {
			return $default;
		}

		$country = strtoupper(substr((string) ($rdap['country'] ?? ''), 0, 2));
		if ($country === '') {
			$country = null;
		}

		$networkName = trim((string) ($rdap['name'] ?? ''));
		$handle = trim((string) ($rdap['handle'] ?? ''));

		$entityOrg = null;
		$entities = $rdap['entities'] ?? null;
		if (is_array($entities)) {
			foreach ($entities as $entity) {
				if (!is_array($entity)) {
					continue;
				}
				$vcardArray = $entity['vcardArray'] ?? null;
				if (!is_array($vcardArray) || !isset($vcardArray[1]) || !is_array($vcardArray[1])) {
					continue;
				}
				foreach ($vcardArray[1] as $vcardItem) {
					if (!is_array($vcardItem) || count($vcardItem) < 4) {
						continue;
					}
					$field = strtolower((string) ($vcardItem[0] ?? ''));
					$value = trim((string) ($vcardItem[3] ?? ''));
					if (($field === 'fn' || $field === 'org') && $value !== '') {
						$entityOrg = $value;
						break 2;
					}
				}
			}
		}

		$asn = null;
		if ($handle !== '' && preg_match('/^AS[0-9]+$/i', $handle) === 1) {
			$asn = strtoupper($handle);
		}

		$asnOrg = null;
		if ($entityOrg !== null && trim($entityOrg) !== '') {
			$asnOrg = trim($entityOrg);
		} elseif ($networkName !== '') {
			$asnOrg = $networkName;
		}

		$ispName = $asnOrg;

		if ($country === null && $asnOrg === null && $ispName === null && $asn === null) {
			$none = $default;
			$none['source'] = 'no_source_result';
			$none['confidence'] = 0.05;
			return $none;
		}

		return [
			'ip_address' => $ipAddress,
			'country_code' => $country,
			'region' => null,
			'city' => null,
			'latitude' => null,
			'longitude' => null,
			'asn' => $asn,
			'asn_org' => $asnOrg,
			'isp_name' => $ispName,
			'is_proxy' => 0,
			'is_hosting' => 0,
			'source' => 'rdap',
			'confidence' => 0.45,
		];
	};

	$url = 'http://ip-api.com/json/' . rawurlencode($ipAddress) . '?fields=status,countryCode,regionName,city,lat,lon,as,isp,proxy,hosting,query';
	$response = false;

	if (function_exists('curl_init')) {
		$ch = curl_init($url);
		if ($ch !== false) {
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
			curl_setopt($ch, CURLOPT_TIMEOUT, 3);
			$response = curl_exec($ch);
			curl_close($ch);
		}
	} else {
		$context = stream_context_create([
			'http' => [
				'timeout' => 3,
			],
		]);
		$response = @file_get_contents($url, false, $context);
	}

	if (!is_string($response) || trim($response) === '') {
		return $rdapFallback();
	}

	$decoded = json_decode($response, true);
	if (!is_array($decoded)) {
		return $rdapFallback();
	}

	$statusValue = strtolower(trim((string) ($decoded['status'] ?? '')));
	if ($statusValue !== 'success') {
		$message = strtolower(trim((string) ($decoded['message'] ?? '')));
		if (
			strpos($message, 'limit') !== false ||
			strpos($message, 'throttle') !== false ||
			strpos($message, 'too many') !== false ||
			strpos($message, 'quota') !== false
		) {
			return $default;
		}
		return $rdapFallback();
	}

	$asnRaw = trim((string) ($decoded['as'] ?? ''));
	$asn = null;
	$asnOrg = null;
	if ($asnRaw !== '') {
		$parts = explode(' ', $asnRaw, 2);
		$asn = $parts[0] ?? null;
		$asnOrg = $parts[1] ?? null;
	}

	return [
		'ip_address' => $ipAddress,
		'country_code' => strtoupper(substr((string) ($decoded['countryCode'] ?? ''), 0, 2)) ?: null,
		'region' => trim((string) ($decoded['regionName'] ?? '')) ?: null,
		'city' => trim((string) ($decoded['city'] ?? '')) ?: null,
		'latitude' => isset($decoded['lat']) ? (float) $decoded['lat'] : null,
		'longitude' => isset($decoded['lon']) ? (float) $decoded['lon'] : null,
		'asn' => $asn,
		'asn_org' => $asnOrg,
		'isp_name' => trim((string) ($decoded['isp'] ?? '')) ?: null,
		'is_proxy' => !empty($decoded['proxy']) ? 1 : 0,
		'is_hosting' => !empty($decoded['hosting']) ? 1 : 0,
		'source' => 'ip-api.com',
		'confidence' => 0.7,
	];
}

function unresolved_enrichment_retry_seconds(): int
{
	$app = app_config()['app'] ?? [];
	$analytics = app_config()['analytics'] ?? [];
	$raw = $app['unresolved_retry_seconds'] ?? $analytics['unresolved_retry_seconds'] ?? app_config()['unresolved_retry_seconds'] ?? 21600;
	$seconds = (int) $raw;
	if ($seconds < 300) {
		$seconds = 300;
	}
	if ($seconds > 604800) {
		$seconds = 604800;
	}

	return $seconds;
}

function ip_enrichment_max_remote_lookups_per_run(): int
{
	$app = app_config()['app'] ?? [];
	$analytics = app_config()['analytics'] ?? [];
	$raw = $app['ip_enrichment_max_remote_lookups_per_run']
		?? $analytics['ip_enrichment_max_remote_lookups_per_run']
		?? app_config()['ip_enrichment_max_remote_lookups_per_run']
		?? 20;
	$limit = (int) $raw;
	if ($limit < 1) {
		$limit = 1;
	}
	if ($limit > 200) {
		$limit = 200;
	}

	return $limit;
}

function upsert_ip_enrichment(array $enrichment): void
{
	$status = analytics_table_status();
	if (!$status['ip_enrichment']) {
		return;
	}

	$stmt = db()->prepare(
		'INSERT INTO pd_ip_enrichment (
			ip_address, country_code, region, city, latitude, longitude, asn, asn_org, isp_name,
			is_proxy, is_hosting, source, confidence, updated_at
		) VALUES (
			:ip_address, :country_code, :region, :city, :latitude, :longitude, :asn, :asn_org, :isp_name,
			:is_proxy, :is_hosting, :source, :confidence, NOW()
		)
		ON DUPLICATE KEY UPDATE
			country_code = VALUES(country_code),
			region = VALUES(region),
			city = VALUES(city),
			latitude = VALUES(latitude),
			longitude = VALUES(longitude),
			asn = VALUES(asn),
			asn_org = VALUES(asn_org),
			isp_name = VALUES(isp_name),
			is_proxy = VALUES(is_proxy),
			is_hosting = VALUES(is_hosting),
			source = VALUES(source),
			confidence = VALUES(confidence),
			updated_at = NOW()'
	);

	$stmt->execute([
		'ip_address' => (string) ($enrichment['ip_address'] ?? ''),
		'country_code' => $enrichment['country_code'] ?? null,
		'region' => $enrichment['region'] ?? null,
		'city' => $enrichment['city'] ?? null,
		'latitude' => $enrichment['latitude'] ?? null,
		'longitude' => $enrichment['longitude'] ?? null,
		'asn' => $enrichment['asn'] ?? null,
		'asn_org' => $enrichment['asn_org'] ?? null,
		'isp_name' => $enrichment['isp_name'] ?? null,
		'is_proxy' => (int) ($enrichment['is_proxy'] ?? 0),
		'is_hosting' => (int) ($enrichment['is_hosting'] ?? 0),
		'source' => (string) ($enrichment['source'] ?? 'unresolved'),
		'confidence' => (float) ($enrichment['confidence'] ?? 0),
	]);
}

function ensure_ip_enrichment(string $ipAddress, bool $allowRemoteLookup = false): array
{
	$default = [
		'ip_address' => $ipAddress,
		'country_code' => null,
		'region' => null,
		'city' => null,
		'latitude' => null,
		'longitude' => null,
		'asn' => null,
		'asn_org' => null,
		'isp_name' => null,
		'is_proxy' => 0,
		'is_hosting' => 0,
		'source' => 'unresolved',
		'confidence' => 0.0,
	];

	$status = analytics_table_status();
	if (!$status['ip_enrichment']) {
		return $default;
	}

	try {
		$existingStmt = db()->prepare('SELECT * FROM pd_ip_enrichment WHERE ip_address = :ip_address LIMIT 1');
		$existingStmt->execute(['ip_address' => $ipAddress]);
		$existing = $existingStmt->fetch();
		if ($existing) {
			$existing['is_proxy'] = (int) ($existing['is_proxy'] ?? 0);
			$existing['is_hosting'] = (int) ($existing['is_hosting'] ?? 0);
			$existing['confidence'] = (float) ($existing['confidence'] ?? 0);
			$existingSource = trim((string) ($existing['source'] ?? ''));
			if (!$allowRemoteLookup || ($existingSource !== '' && $existingSource !== 'unresolved')) {
				return $existing;
			}

			$updatedAt = parse_db_datetime_utc((string) ($existing['updated_at'] ?? ''));
			if ($updatedAt instanceof DateTimeImmutable) {
				$ageSeconds = time() - $updatedAt->getTimestamp();
				if ($ageSeconds >= 0 && $ageSeconds < unresolved_enrichment_retry_seconds()) {
					return $existing;
				}
			}
		}
	} catch (Throwable $e) {
		return $default;
	}

	if (!$allowRemoteLookup) {
		return $default;
	}

	$enrichment = lookup_ip_enrichment_remote($ipAddress);

	try {
		upsert_ip_enrichment($enrichment);
	} catch (Throwable $e) {
	}

	return $enrichment;
}

function classify_and_store_hit(int $hitId, int $pixelId, string $pixelKey, array $hitData, bool $allowRemoteLookup = false): void
{
	$status = analytics_table_status();
	if (!$status['hit_classification']) {
		return;
	}

	$ipAddress = trim((string) ($hitData['ip_address'] ?? ''));
	$enrichment = $ipAddress !== '' ? ensure_ip_enrichment($ipAddress, $allowRemoteLookup) : [
		'is_proxy' => 0,
		'isp_name' => null,
		'reverse_host' => null,
	];
	$resolvedRemoteHost = trim((string) ($hitData['remote_host'] ?? ''));
	if ($resolvedRemoteHost === '') {
		$resolvedRemoteHost = trim((string) ($enrichment['reverse_host'] ?? ''));
	}
	$hitData['remote_host'] = $resolvedRemoteHost;
	if (!isset($hitData['source_type'])) {
		$hitData['source_type'] = 'pixel';
	}

	$email = infer_email_client($hitData);
	$remoteHostIsp = infer_isp_from_remote_host($resolvedRemoteHost);
	$asnIsp = trim((string) ($enrichment['asn_org'] ?? ''));
	$ispName = trim((string) ($enrichment['isp_name'] ?? ''));

	$ispGuess = null;
	$ispSource = 'unknown';
	if ($remoteHostIsp !== null && $remoteHostIsp !== '') {
		$ispGuess = $remoteHostIsp;
		$ispSource = 'remote_host';
	} elseif ($ispName !== '') {
		$ispGuess = $ispName;
		$ispSource = 'geo_isp';
	} elseif ($asnIsp !== '') {
		$ispGuess = $asnIsp;
		$ispSource = 'asn';
	}

	$trafficType = infer_traffic_type($hitData, $enrichment, (string) $email['client']);

	$stmt = db()->prepare(
		'INSERT INTO pd_hit_classification (
			hit_id, pixel_id, pixel_key, ip_address, email_client_guess, email_client_confidence,
			traffic_type, isp_guess, isp_source, classified_at
		) VALUES (
			:hit_id, :pixel_id, :pixel_key, :ip_address, :email_client_guess, :email_client_confidence,
			:traffic_type, :isp_guess, :isp_source, NOW()
		)
		ON DUPLICATE KEY UPDATE
			pixel_id = VALUES(pixel_id),
			pixel_key = VALUES(pixel_key),
			ip_address = VALUES(ip_address),
			email_client_guess = VALUES(email_client_guess),
			email_client_confidence = VALUES(email_client_confidence),
			traffic_type = VALUES(traffic_type),
			isp_guess = VALUES(isp_guess),
			isp_source = VALUES(isp_source),
			classified_at = NOW()'
	);

	$stmt->execute([
		'hit_id' => $hitId,
		'pixel_id' => $pixelId,
		'pixel_key' => $pixelKey,
		'ip_address' => $ipAddress,
		'email_client_guess' => (string) $email['client'],
		'email_client_confidence' => (float) $email['confidence'],
		'traffic_type' => $trafficType,
		'isp_guess' => $ispGuess,
		'isp_source' => $ispSource,
	]);
}

function backfill_hit_classification_for_pixel(int $pixelId, int $limit = 100, bool $allowRemoteLookup = false): int
{
	$status = analytics_table_status();
	if (!$status['hit_classification']) {
		return 0;
	}

	$limit = max(1, min(500, $limit));
	$stmt = db()->prepare(
		'SELECT h.id, h.pixel_id, h.pixel_key, h.ip_address, h.user_agent, h.referrer, h.request_uri, h.accept_language, h.remote_host
		 FROM pd_pixel_hits h
		 LEFT JOIN pd_hit_classification c ON c.hit_id = h.id
		 WHERE h.pixel_id = :pixel_id AND c.hit_id IS NULL
		 ORDER BY h.id DESC
		 LIMIT :limit'
	);
	$stmt->bindValue(':pixel_id', $pixelId, PDO::PARAM_INT);
	$stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
	$stmt->execute();

	$rows = $stmt->fetchAll();
	foreach ($rows as $row) {
		try {
			classify_and_store_hit(
				(int) $row['id'],
				(int) $row['pixel_id'],
				(string) $row['pixel_key'],
				[
					'ip_address' => (string) ($row['ip_address'] ?? ''),
					'user_agent' => (string) ($row['user_agent'] ?? ''),
					'referrer' => (string) ($row['referrer'] ?? ''),
					'request_uri' => (string) ($row['request_uri'] ?? ''),
					'accept_language' => (string) ($row['accept_language'] ?? ''),
					'remote_host' => (string) ($row['remote_host'] ?? ''),
				],
				$allowRemoteLookup
			);
		} catch (Throwable $e) {
		}
	}

	return count($rows);
}

function create_redirect_link(string $redirectKey, string $destinationUrl, ?int $createdBy = null): int
{
	$redirectKey = sanitize_redirect_key($redirectKey);
	if ($redirectKey === '') {
		throw new InvalidArgumentException('Redirect key is required.');
	}

	$destinationUrl = trim($destinationUrl);
	if ($destinationUrl === '' || !filter_var($destinationUrl, FILTER_VALIDATE_URL)) {
		throw new InvalidArgumentException('Destination URL must be a valid URL.');
	}

	$scheme = strtolower((string) parse_url($destinationUrl, PHP_URL_SCHEME));
	if (!in_array($scheme, ['http', 'https'], true)) {
		throw new InvalidArgumentException('Destination URL must be http or https.');
	}

	$stmt = db()->prepare('SELECT id FROM pd_redirect_links WHERE redirect_key = :redirect_key LIMIT 1');
	$stmt->execute(['redirect_key' => $redirectKey]);
	$existing = $stmt->fetch();
	if ($existing) {
		throw new RuntimeException('Redirect key already exists.');
	}

	$insert = db()->prepare(
		'INSERT INTO pd_redirect_links (redirect_key, destination_url, is_active, created_by, created_at, updated_at, total_hits)
		 VALUES (:redirect_key, :destination_url, 1, :created_by, NOW(), NOW(), 0)'
	);
	$insert->execute([
		'redirect_key' => $redirectKey,
		'destination_url' => $destinationUrl,
		'created_by' => $createdBy,
	]);

	return (int) db()->lastInsertId();
}

function classify_and_store_redirect_hit(int $hitId, int $redirectId, string $redirectKey, array $hitData, bool $allowRemoteLookup = false): void
{
	$status = analytics_table_status();
	if (!$status['redirect_hit_classification']) {
		return;
	}

	$ipAddress = trim((string) ($hitData['ip_address'] ?? ''));
	$enrichment = $ipAddress !== '' ? ensure_ip_enrichment($ipAddress, $allowRemoteLookup) : [
		'is_proxy' => 0,
		'isp_name' => null,
		'reverse_host' => null,
	];
	$resolvedRemoteHost = trim((string) ($hitData['remote_host'] ?? ''));
	if ($resolvedRemoteHost === '') {
		$resolvedRemoteHost = trim((string) ($enrichment['reverse_host'] ?? ''));
	}
	$hitData['remote_host'] = $resolvedRemoteHost;
	if (!isset($hitData['source_type'])) {
		$hitData['source_type'] = 'redirect';
	}

	$email = infer_email_client($hitData);
	$remoteHostIsp = infer_isp_from_remote_host($resolvedRemoteHost);
	$asnIsp = trim((string) ($enrichment['asn_org'] ?? ''));
	$ispName = trim((string) ($enrichment['isp_name'] ?? ''));

	$ispGuess = null;
	$ispSource = 'unknown';
	if ($remoteHostIsp !== null && $remoteHostIsp !== '') {
		$ispGuess = $remoteHostIsp;
		$ispSource = 'remote_host';
	} elseif ($ispName !== '') {
		$ispGuess = $ispName;
		$ispSource = 'geo_isp';
	} elseif ($asnIsp !== '') {
		$ispGuess = $asnIsp;
		$ispSource = 'asn';
	}

	$trafficType = infer_traffic_type($hitData, $enrichment, (string) $email['client']);

	$stmt = db()->prepare(
		'INSERT INTO pd_redirect_hit_classification (
			hit_id, redirect_id, redirect_key, ip_address, email_client_guess, email_client_confidence,
			traffic_type, isp_guess, isp_source, classified_at
		) VALUES (
			:hit_id, :redirect_id, :redirect_key, :ip_address, :email_client_guess, :email_client_confidence,
			:traffic_type, :isp_guess, :isp_source, NOW()
		)
		ON DUPLICATE KEY UPDATE
			redirect_id = VALUES(redirect_id),
			redirect_key = VALUES(redirect_key),
			ip_address = VALUES(ip_address),
			email_client_guess = VALUES(email_client_guess),
			email_client_confidence = VALUES(email_client_confidence),
			traffic_type = VALUES(traffic_type),
			isp_guess = VALUES(isp_guess),
			isp_source = VALUES(isp_source),
			classified_at = NOW()'
	);

	$stmt->execute([
		'hit_id' => $hitId,
		'redirect_id' => $redirectId,
		'redirect_key' => $redirectKey,
		'ip_address' => $ipAddress,
		'email_client_guess' => (string) $email['client'],
		'email_client_confidence' => (float) $email['confidence'],
		'traffic_type' => $trafficType,
		'isp_guess' => $ispGuess,
		'isp_source' => $ispSource,
	]);
}

function backfill_hit_classification_for_redirect(int $redirectId, int $limit = 100, bool $allowRemoteLookup = false): int
{
	$status = analytics_table_status();
	if (!$status['redirect_hit_classification']) {
		return 0;
	}

	$limit = max(1, min(500, $limit));
	$stmt = db()->prepare(
		'SELECT h.id, h.redirect_id, h.redirect_key, h.ip_address, h.user_agent, h.referrer, h.request_uri, h.accept_language, h.remote_host
		 FROM pd_redirect_hits h
		 LEFT JOIN pd_redirect_hit_classification c ON c.hit_id = h.id
		 WHERE h.redirect_id = :redirect_id AND c.hit_id IS NULL
		 ORDER BY h.id DESC
		 LIMIT :limit'
	);
	$stmt->bindValue(':redirect_id', $redirectId, PDO::PARAM_INT);
	$stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
	$stmt->execute();

	$rows = $stmt->fetchAll();
	foreach ($rows as $row) {
		try {
			classify_and_store_redirect_hit(
				(int) $row['id'],
				(int) $row['redirect_id'],
				(string) $row['redirect_key'],
				[
					'ip_address' => (string) ($row['ip_address'] ?? ''),
					'user_agent' => (string) ($row['user_agent'] ?? ''),
					'referrer' => (string) ($row['referrer'] ?? ''),
					'request_uri' => (string) ($row['request_uri'] ?? ''),
					'accept_language' => (string) ($row['accept_language'] ?? ''),
					'remote_host' => (string) ($row['remote_host'] ?? ''),
				],
				$allowRemoteLookup
			);
		} catch (Throwable $e) {
		}
	}

	return count($rows);
}

function can_spawn_background_process(): bool
{
	if (!function_exists('exec')) {
		return false;
	}

	$disabled = (string) ini_get('disable_functions');
	if ($disabled !== '') {
		$parts = array_map('trim', explode(',', $disabled));
		if (in_array('exec', $parts, true)) {
			return false;
		}
	}

	return true;
}

function enqueue_ip_for_enrichment(string $ipAddress): void
{
	$ipAddress = trim($ipAddress);
	if ($ipAddress === '' || strlen($ipAddress) > 45) {
		return;
	}

	$status = analytics_table_status();
	if (!$status['ip_queue']) {
		return;
	}

	$stmt = db()->prepare(
		'INSERT INTO pd_ip_enrichment_queue (
			ip_address, first_seen_at, last_seen_at, next_attempt_at, attempt_count, last_error, processed_at, created_at, updated_at
		) VALUES (
			:ip_address, NOW(), NOW(), NOW(), 0, NULL, NULL, NOW(), NOW()
		)
		ON DUPLICATE KEY UPDATE
			last_seen_at = NOW(),
			updated_at = NOW(),
			next_attempt_at = IF(next_attempt_at > NOW(), NOW(), next_attempt_at)'
	);

	$stmt->execute(['ip_address' => $ipAddress]);
}

function try_start_ip_enrichment_worker(int $minSpawnIntervalSeconds = 30): bool
{
	if (!can_spawn_background_process()) {
		return false;
	}

	$status = analytics_table_status();
	if (!$status['ip_queue']) {
		return false;
	}

	$lockFile = sys_get_temp_dir() . '/pixeldust_ip_worker_last_spawn.lock';
	$now = time();
	$lastSpawn = @file_exists($lockFile) ? (int) @filemtime($lockFile) : 0;
	if ($lastSpawn > 0 && ($now - $lastSpawn) < max(1, $minSpawnIntervalSeconds)) {
		return false;
	}

	$workerScript = dirname(__DIR__) . '/workers/ip_enrichment_worker.php';
	if (!is_file($workerScript)) {
		return false;
	}

	@touch($lockFile);

	$phpBinary = PHP_BINARY;
	if (!is_string($phpBinary) || trim($phpBinary) === '') {
		$phpBinary = 'php';
	}

	$cmd = escapeshellarg($phpBinary) . ' ' . escapeshellarg($workerScript) . ' >/dev/null 2>&1 &';
	@exec($cmd);

	return true;
}

function analytics_access_log_path(): ?string
{
	$app = app_config()['app'] ?? [];
	$analytics = app_config()['analytics'] ?? [];
	$path = trim((string) ($app['access_log_path'] ?? $analytics['access_log_path'] ?? app_config()['access_log_path'] ?? ''));
	if ($path === '') {
		return null;
	}

	if (!is_file($path) || !is_readable($path)) {
		return null;
	}

	return $path;
}

function analytics_access_log_max_lines_per_run(): int
{
	$app = app_config()['app'] ?? [];
	$analytics = app_config()['analytics'] ?? [];
	$raw = $app['access_log_max_lines_per_run'] ?? $analytics['access_log_max_lines_per_run'] ?? app_config()['access_log_max_lines_per_run'] ?? 1200;
	$limit = (int) $raw;
	if ($limit < 100) {
		$limit = 100;
	}
	if ($limit > 20000) {
		$limit = 20000;
	}

	return $limit;
}

function analytics_access_log_cursor_path(string $logPath): string
{
	return rtrim(sys_get_temp_dir(), '/') . '/pixeldust_access_log_' . md5($logPath) . '.cursor.json';
}

function load_access_log_cursor(string $logPath): array
{
	$cursorPath = analytics_access_log_cursor_path($logPath);
	if (!is_file($cursorPath) || !is_readable($cursorPath)) {
		return ['inode' => 0, 'offset' => 0];
	}

	$json = @file_get_contents($cursorPath);
	if (!is_string($json) || trim($json) === '') {
		return ['inode' => 0, 'offset' => 0];
	}

	$decoded = json_decode($json, true);
	if (!is_array($decoded)) {
		return ['inode' => 0, 'offset' => 0];
	}

	return [
		'inode' => (int) ($decoded['inode'] ?? 0),
		'offset' => (int) ($decoded['offset'] ?? 0),
	];
}

function save_access_log_cursor(string $logPath, int $inode, int $offset): void
{
	$cursorPath = analytics_access_log_cursor_path($logPath);
	@file_put_contents($cursorPath, json_encode([
		'inode' => $inode,
		'offset' => max(0, $offset),
		'updated_at' => gmdate('c'),
	], JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function parse_apache_access_log_raw_line(string $line): ?array
{
	$line = trim($line);
	if ($line === '') {
		return null;
	}

	$matched = preg_match(
		'/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\"]+)\s+HTTP\/[0-9.]+"\s+\d+\s+\S+\s+"([^\"]*)"\s+"([^\"]*)"/',
		$line,
		$parts
	);
	if ($matched !== 1) {
		return null;
	}

	$ipAddress = trim((string) ($parts[1] ?? ''));
	$timeRaw = trim((string) ($parts[2] ?? ''));
	$method = strtoupper(trim((string) ($parts[3] ?? '')));
	$requestTarget = trim((string) ($parts[4] ?? ''));
	$referrer = trim((string) ($parts[5] ?? ''));
	$userAgent = trim((string) ($parts[6] ?? ''));

	if ($ipAddress === '' || $requestTarget === '') {
		return null;
	}

	if ($referrer === '-') {
		$referrer = '';
	}

	$hitTime = DateTimeImmutable::createFromFormat('d/M/Y:H:i:s O', $timeRaw);
	if (!$hitTime) {
		return null;
	}

	$path = '';
	$query = '';
	if (preg_match('/^https?:\/\//i', $requestTarget) === 1) {
		$parsedPath = parse_url($requestTarget, PHP_URL_PATH);
		$parsedQuery = parse_url($requestTarget, PHP_URL_QUERY);
		$path = is_string($parsedPath) ? $parsedPath : '';
		$query = is_string($parsedQuery) ? $parsedQuery : '';
	} else {
		$path = (string) parse_url($requestTarget, PHP_URL_PATH);
		$query = (string) parse_url($requestTarget, PHP_URL_QUERY);
	}

	$path = trim($path);
	$query = trim($query);
	if ($path === '') {
		$path = '/';
	}

	$scriptName = strtolower((string) basename($path));
	$sourceType = null;
	if ($scriptName === 'pix.php') {
		$sourceType = 'pixel';
	} elseif ($scriptName === 'link.php') {
		$sourceType = 'redirect';
	}

	$requestUri = $path . ($query !== '' ? '?' . $query : '');

	return [
		'source_type' => $sourceType,
		'ip_address' => $ipAddress,
		'hit_at_utc' => $hitTime->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
		'method' => $method,
		'referrer' => substr($referrer, 0, 2048),
		'user_agent' => substr($userAgent, 0, 1024),
		'request_uri' => $requestUri,
		'query_string' => $query,
		'path' => $path,
	];
}

function parse_apache_access_log_line(string $line): ?array
{
	$raw = parse_apache_access_log_raw_line($line);
	if (!is_array($raw)) {
		return null;
	}

	if (!in_array((string) ($raw['source_type'] ?? ''), ['pixel', 'redirect'], true)) {
		return null;
	}

	return $raw;
}

function normalize_source_attribution_value(string $value): string
{
	$value = trim($value);
	if ($value === '' || $value === '-') {
		return '';
	}

	if (filter_var($value, FILTER_VALIDATE_URL)) {
		return $value;
	}

	if (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}(?:\/.*)?$/i', $value) === 1) {
		$asUrl = 'https://' . ltrim($value, '/');
		if (filter_var($asUrl, FILTER_VALIDATE_URL)) {
			return $asUrl;
		}
	}

	$value = preg_replace('/[^a-z0-9._\-]+/i', '_', $value);
	$value = trim((string) $value, '_');
	if ($value === '') {
		return '';
	}

	return 'tag://' . $value;
}

function extract_source_attribution_from_query(string $queryString): string
{
	$queryString = trim($queryString);
	if ($queryString === '') {
		return '';
	}

	$params = [];
	parse_str($queryString, $params);
	if (!is_array($params) || !$params) {
		return '';
	}

	$candidateKeys = ['ref', 'utm_source', 'source', 'src', 'from', 'campaign_source'];
	foreach ($candidateKeys as $key) {
		if (!array_key_exists($key, $params)) {
			continue;
		}
		$value = $params[$key];
		if (is_array($value)) {
			$value = (string) reset($value);
		}
		$normalized = normalize_source_attribution_value((string) $value);
		if ($normalized !== '') {
			return $normalized;
		}
	}

	return '';
}

function derive_source_attribution_referrer(array $event, ?array $chainHint = null): string
{
	$existingReferrer = normalize_source_attribution_value((string) ($event['referrer'] ?? ''));
	if ($existingReferrer !== '') {
		return $existingReferrer;
	}

	$queryHint = extract_source_attribution_from_query((string) ($event['query_string'] ?? ''));
	if ($queryHint !== '') {
		return $queryHint;
	}

	if (is_array($chainHint)) {
		$chainReferrer = normalize_source_attribution_value((string) ($chainHint['referrer'] ?? ''));
		$chainSeenAt = parse_db_datetime_utc((string) ($chainHint['seen_at'] ?? ''));
		$eventTime = parse_db_datetime_utc((string) ($event['hit_at_utc'] ?? ''));
		if ($chainReferrer !== '' && $chainSeenAt && $eventTime) {
			$age = abs($eventTime->getTimestamp() - $chainSeenAt->getTimestamp());
			if ($age <= 20 * 60) {
				return $chainReferrer;
			}
		}
	}

	return '';
}

function record_traffic_fingerprint_observation(array $event): bool
{
	$status = analytics_table_status();
	if (!(bool) ($status['traffic_fingerprints'] ?? false)) {
		return false;
	}

	$sourceType = trim((string) ($event['source_type'] ?? ''));
	$userAgent = trim((string) ($event['user_agent'] ?? ''));
	$ipAddress = trim((string) ($event['ip_address'] ?? ''));
	$hitAtUtc = trim((string) ($event['hit_at_utc'] ?? ''));
	$requestPath = extract_request_path_from_uri((string) ($event['request_uri'] ?? ''));

	if (!in_array($sourceType, ['pixel', 'redirect'], true) || $userAgent === '' || $ipAddress === '' || $hitAtUtc === '') {
		return false;
	}

	$fingerprintKey = traffic_fingerprint_key($sourceType, $requestPath, $userAgent);
	$userAgentHash = sha1(strtolower($userAgent));
	$userAgentSample = function_exists('mb_substr') ? (string) mb_substr($userAgent, 0, 255) : substr($userAgent, 0, 255);

	try {
		$select = db()->prepare(
			'SELECT hit_count, distinct_ip_count, last_ip_address, last_seen_at, avg_interval_seconds, min_interval_seconds
			 FROM pd_traffic_fingerprint_library
			 WHERE fingerprint_key = :fingerprint_key
			 LIMIT 1'
		);
		$select->execute(['fingerprint_key' => $fingerprintKey]);
		$existing = $select->fetch();

		if (!$existing) {
			$obs = infer_traffic_classification_from_observation($userAgent, 1, 1, null, null);
			$insert = db()->prepare(
				'INSERT INTO pd_traffic_fingerprint_library (
					fingerprint_key, source_type, endpoint_path, user_agent_hash, user_agent_sample,
					hit_count, distinct_ip_count, last_ip_address, last_seen_at,
					avg_interval_seconds, min_interval_seconds, classification, confidence, updated_at
				) VALUES (
					:fingerprint_key, :source_type, :endpoint_path, :user_agent_hash, :user_agent_sample,
					1, 1, :last_ip_address, :last_seen_at,
					NULL, NULL, :classification, :confidence, NOW()
				)'
			);
			$insert->execute([
				'fingerprint_key' => $fingerprintKey,
				'source_type' => $sourceType,
				'endpoint_path' => $requestPath,
				'user_agent_hash' => $userAgentHash,
				'user_agent_sample' => $userAgentSample,
				'last_ip_address' => $ipAddress,
				'last_seen_at' => $hitAtUtc,
				'classification' => (string) ($obs['classification'] ?? 'unknown'),
				'confidence' => (float) ($obs['confidence'] ?? 0),
			]);
			return true;
		}

		$existingHitCount = (int) ($existing['hit_count'] ?? 0);
		$existingDistinctIpCount = (int) ($existing['distinct_ip_count'] ?? 0);
		$existingLastIp = trim((string) ($existing['last_ip_address'] ?? ''));
		$existingLastSeen = parse_db_datetime_utc((string) ($existing['last_seen_at'] ?? ''));
		$eventSeen = parse_db_datetime_utc($hitAtUtc);

		$intervalSeconds = null;
		if ($existingLastSeen && $eventSeen) {
			$intervalSeconds = max(0, $eventSeen->getTimestamp() - $existingLastSeen->getTimestamp());
		}

		$newHitCount = $existingHitCount + 1;
		$newDistinctIpCount = $existingDistinctIpCount + (($existingLastIp !== '' && $existingLastIp !== $ipAddress) ? 1 : 0);
		$avgInterval = $existing['avg_interval_seconds'] !== null ? (float) $existing['avg_interval_seconds'] : null;
		if ($intervalSeconds !== null) {
			if ($avgInterval === null || $existingHitCount <= 0) {
				$avgInterval = (float) $intervalSeconds;
			} else {
				$avgInterval = (($avgInterval * max(1, $existingHitCount - 1)) + $intervalSeconds) / max(1, $existingHitCount);
			}
		}

		$minInterval = $existing['min_interval_seconds'] !== null ? (int) $existing['min_interval_seconds'] : null;
		if ($intervalSeconds !== null) {
			$minInterval = $minInterval === null ? $intervalSeconds : min($minInterval, $intervalSeconds);
		}

		$obs = infer_traffic_classification_from_observation($userAgent, $newHitCount, $newDistinctIpCount, $avgInterval, $minInterval);

		$update = db()->prepare(
			'UPDATE pd_traffic_fingerprint_library
			 SET source_type = :source_type,
			     endpoint_path = :endpoint_path,
			     user_agent_hash = :user_agent_hash,
			     user_agent_sample = :user_agent_sample,
			     hit_count = :hit_count,
			     distinct_ip_count = :distinct_ip_count,
			     last_ip_address = :last_ip_address,
			     last_seen_at = :last_seen_at,
			     avg_interval_seconds = :avg_interval_seconds,
			     min_interval_seconds = :min_interval_seconds,
			     classification = :classification,
			     confidence = :confidence,
			     updated_at = NOW()
			 WHERE fingerprint_key = :fingerprint_key'
		);
		$update->execute([
			'source_type' => $sourceType,
			'endpoint_path' => $requestPath,
			'user_agent_hash' => $userAgentHash,
			'user_agent_sample' => $userAgentSample,
			'hit_count' => $newHitCount,
			'distinct_ip_count' => $newDistinctIpCount,
			'last_ip_address' => $ipAddress,
			'last_seen_at' => $hitAtUtc,
			'avg_interval_seconds' => $avgInterval,
			'min_interval_seconds' => $minInterval,
			'classification' => (string) ($obs['classification'] ?? 'unknown'),
			'confidence' => (float) ($obs['confidence'] ?? 0),
			'fingerprint_key' => $fingerprintKey,
		]);
		return true;
	} catch (Throwable $e) {
		return false;
	}
}

function match_access_log_referrer_to_hit(array $event): bool
{
	$sourceType = (string) ($event['source_type'] ?? '');
	$ipAddress = trim((string) ($event['ip_address'] ?? ''));
	$hitAtUtc = trim((string) ($event['hit_at_utc'] ?? ''));
	$referrer = trim((string) ($event['referrer'] ?? ''));
	$userAgent = trim((string) ($event['user_agent'] ?? ''));
	$queryString = trim((string) ($event['query_string'] ?? ''));
	$requestUri = trim((string) ($event['request_uri'] ?? ''));

	if ($ipAddress === '' || $hitAtUtc === '' || $referrer === '') {
		return false;
	}

	$hitTime = parse_db_datetime_utc($hitAtUtc);
	if (!$hitTime) {
		return false;
	}

	$windowStart = $hitTime->sub(new DateInterval('PT10M'))->format('Y-m-d H:i:s');
	$windowEnd = $hitTime->add(new DateInterval('PT10M'))->format('Y-m-d H:i:s');

	try {
		$pdo = db();

		if ($sourceType === 'pixel') {
			if (!table_exists($pdo, 'pd_pixel_hits')) {
				return false;
			}

			$whereClause = '';
			if ($queryString !== '') {
				$whereClause = ' AND query_string = :query_string';
			} elseif ($requestUri !== '') {
				$whereClause = ' AND request_uri LIKE :request_uri_like';
			}

			$uaClause = $userAgent !== '' ? " AND (user_agent = :user_agent OR user_agent IS NULL OR TRIM(user_agent) = '')" : '';
			$select = db()->prepare(
				"SELECT id, pixel_id, pixel_key, ip_address, user_agent, request_uri, accept_language, remote_host
				 FROM pd_pixel_hits
				 WHERE ip_address = :ip_address
				   AND (referrer IS NULL OR TRIM(referrer) = '')
				   AND hit_at BETWEEN :window_start AND :window_end
				   $uaClause
				   $whereClause
				 ORDER BY ABS(TIMESTAMPDIFF(SECOND, hit_at, :event_time)) ASC, id DESC
				 LIMIT 1"
			);
			$select->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
			$select->bindValue(':window_start', $windowStart, PDO::PARAM_STR);
			$select->bindValue(':window_end', $windowEnd, PDO::PARAM_STR);
			$select->bindValue(':event_time', $hitAtUtc, PDO::PARAM_STR);
			if ($queryString !== '') {
				$select->bindValue(':query_string', $queryString, PDO::PARAM_STR);
			} elseif ($requestUri !== '') {
				$select->bindValue(':request_uri_like', '%' . $requestUri . '%', PDO::PARAM_STR);
			}
			if ($userAgent !== '') {
				$select->bindValue(':user_agent', $userAgent, PDO::PARAM_STR);
			}
			$select->execute();
			$row = $select->fetch();
			if (!$row) {
				return false;
			}

			$update = db()->prepare('UPDATE pd_pixel_hits SET referrer = :referrer WHERE id = :id');
			$update->execute([
				'referrer' => $referrer,
				'id' => (int) $row['id'],
			]);

			try {
				classify_and_store_hit(
					(int) $row['id'],
					(int) $row['pixel_id'],
					(string) $row['pixel_key'],
					[
						'ip_address' => (string) ($row['ip_address'] ?? ''),
						'user_agent' => (string) ($row['user_agent'] ?? ''),
						'referrer' => $referrer,
						'request_uri' => (string) ($row['request_uri'] ?? ''),
						'accept_language' => (string) ($row['accept_language'] ?? ''),
						'source_type' => 'pixel',
						'remote_host' => (string) ($row['remote_host'] ?? ''),
					],
					false
				);
			} catch (Throwable $e) {
			}

			return true;
		}

		if ($sourceType === 'redirect') {
			if (!table_exists($pdo, 'pd_redirect_hits')) {
				return false;
			}

			$whereClause = '';
			if ($queryString !== '') {
				$whereClause = ' AND query_string = :query_string';
			} elseif ($requestUri !== '') {
				$whereClause = ' AND request_uri LIKE :request_uri_like';
			}

			$uaClause = $userAgent !== '' ? " AND (user_agent = :user_agent OR user_agent IS NULL OR TRIM(user_agent) = '')" : '';
			$select = db()->prepare(
				"SELECT id, redirect_id, redirect_key, ip_address, user_agent, request_uri, accept_language, remote_host
				 FROM pd_redirect_hits
				 WHERE ip_address = :ip_address
				   AND (referrer IS NULL OR TRIM(referrer) = '')
				   AND hit_at BETWEEN :window_start AND :window_end
				   $uaClause
				   $whereClause
				 ORDER BY ABS(TIMESTAMPDIFF(SECOND, hit_at, :event_time)) ASC, id DESC
				 LIMIT 1"
			);
			$select->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
			$select->bindValue(':window_start', $windowStart, PDO::PARAM_STR);
			$select->bindValue(':window_end', $windowEnd, PDO::PARAM_STR);
			$select->bindValue(':event_time', $hitAtUtc, PDO::PARAM_STR);
			if ($queryString !== '') {
				$select->bindValue(':query_string', $queryString, PDO::PARAM_STR);
			} elseif ($requestUri !== '') {
				$select->bindValue(':request_uri_like', '%' . $requestUri . '%', PDO::PARAM_STR);
			}
			if ($userAgent !== '') {
				$select->bindValue(':user_agent', $userAgent, PDO::PARAM_STR);
			}
			$select->execute();
			$row = $select->fetch();
			if (!$row) {
				return false;
			}

			$update = db()->prepare('UPDATE pd_redirect_hits SET referrer = :referrer WHERE id = :id');
			$update->execute([
				'referrer' => $referrer,
				'id' => (int) $row['id'],
			]);

			try {
				classify_and_store_redirect_hit(
					(int) $row['id'],
					(int) $row['redirect_id'],
					(string) $row['redirect_key'],
					[
						'ip_address' => (string) ($row['ip_address'] ?? ''),
						'user_agent' => (string) ($row['user_agent'] ?? ''),
						'referrer' => $referrer,
						'request_uri' => (string) ($row['request_uri'] ?? ''),
						'accept_language' => (string) ($row['accept_language'] ?? ''),
						'source_type' => 'redirect',
						'remote_host' => (string) ($row['remote_host'] ?? ''),
					],
					false
				);
			} catch (Throwable $e) {
			}

			return true;
		}
	} catch (Throwable $e) {
		return false;
	}

	return false;
}

function process_access_log_referrer_enrichment(int $maxLines = 2500): array
{
	$logPath = analytics_access_log_path();
	if ($logPath === null) {
		return [
			'enabled' => false,
			'processed_lines' => 0,
			'matched_events' => 0,
			'updated_hits' => 0,
		];
	}

	$maxLines = max(100, min(20000, $maxLines));
	$fileStat = @stat($logPath);
	if (!is_array($fileStat)) {
		return [
			'enabled' => true,
			'processed_lines' => 0,
			'matched_events' => 0,
			'updated_hits' => 0,
			'error' => 'access_log_unreadable',
		];
	}

	$inode = (int) ($fileStat['ino'] ?? 0);
	$size = (int) ($fileStat['size'] ?? 0);
	$cursor = load_access_log_cursor($logPath);
	$offset = (int) ($cursor['offset'] ?? 0);
	$previousInode = (int) ($cursor['inode'] ?? 0);

	if ($offset < 0 || $size < $offset || ($previousInode > 0 && $previousInode !== $inode)) {
		$offset = 0;
	}

	$handle = @fopen($logPath, 'rb');
	if ($handle === false) {
		return [
			'enabled' => true,
			'processed_lines' => 0,
			'matched_events' => 0,
			'updated_hits' => 0,
			'error' => 'access_log_open_failed',
		];
	}

	if ($offset > 0) {
		@fseek($handle, $offset);
	}

	$processedLines = 0;
	$matchedEvents = 0;
	$updatedHits = 0;
	$attributedHits = 0;
	$fingerprintUpdates = 0;
	$actorReferrerChain = [];

	while (!feof($handle) && $processedLines < $maxLines) {
		$line = fgets($handle);
		if ($line === false) {
			break;
		}

		$processedLines++;
		$currentOffset = ftell($handle);
		if (is_int($currentOffset) && $currentOffset >= 0) {
			$offset = $currentOffset;
		}

		$rawEvent = parse_apache_access_log_raw_line($line);
		if (!$rawEvent) {
			continue;
		}

		$actorKey = trim((string) ($rawEvent['ip_address'] ?? '')) . '|' . sha1(strtolower(trim((string) ($rawEvent['user_agent'] ?? ''))));
		$rawReferrer = normalize_source_attribution_value((string) ($rawEvent['referrer'] ?? ''));
		if ($rawReferrer !== '') {
			$actorReferrerChain[$actorKey] = [
				'referrer' => $rawReferrer,
				'seen_at' => (string) ($rawEvent['hit_at_utc'] ?? ''),
			];
		}

		if (!in_array((string) ($rawEvent['source_type'] ?? ''), ['pixel', 'redirect'], true)) {
			continue;
		}

		$event = $rawEvent;
		if (trim((string) ($event['referrer'] ?? '')) === '') {
			$event['referrer'] = derive_source_attribution_referrer($event, $actorReferrerChain[$actorKey] ?? null);
		}

		$matchedEvents++;
		if (record_traffic_fingerprint_observation($event)) {
			$fingerprintUpdates++;
		}
		if (match_access_log_referrer_to_hit($event)) {
			$updatedHits++;
			if (extract_source_attribution_from_query((string) ($event['query_string'] ?? '')) !== '') {
				$attributedHits++;
			}
		}
	}

	fclose($handle);
	save_access_log_cursor($logPath, $inode, $offset);

	return [
		'enabled' => true,
		'path' => $logPath,
		'processed_lines' => $processedLines,
		'matched_events' => $matchedEvents,
		'updated_hits' => $updatedHits,
		'attributed_hits' => $attributedHits,
		'fingerprint_updates' => $fingerprintUpdates,
	];
}

function process_ip_enrichment_queue(int $maxRows = 100, int $maxRuntimeSeconds = 8): array
{
	$status = analytics_table_status();
	$hasIpQueue = $status['ip_queue'] && $status['ip_enrichment'];
	$hasAccessLog = analytics_access_log_path() !== null;

	if (!$hasIpQueue && !$hasAccessLog) {
		return [
			'processed' => 0,
			'succeeded' => 0,
			'failed' => 0,
			'auto_bot_tagged' => 0,
			'locked' => false,
			'access_log' => [
				'enabled' => false,
				'processed_lines' => 0,
				'matched_events' => 0,
				'updated_hits' => 0,
			],
		];
	}

	$maxRows = max(1, min(1000, $maxRows));
	$maxRuntimeSeconds = max(1, min(60, $maxRuntimeSeconds));
	$startedAt = microtime(true);

	$lockStmt = db()->prepare('SELECT GET_LOCK(:lock_name, 0) AS got_lock');
	$lockStmt->execute(['lock_name' => 'pixeldust_ip_enrichment_worker']);
	$gotLock = (int) ($lockStmt->fetch()['got_lock'] ?? 0) === 1;
	if (!$gotLock) {
		return ['processed' => 0, 'succeeded' => 0, 'failed' => 0, 'auto_bot_tagged' => 0, 'locked' => true];
	}

	$processed = 0;
	$succeeded = 0;
	$failed = 0;
	$autoBotTagged = 0;
	$maxRemoteLookups = ip_enrichment_max_remote_lookups_per_run();
	$remoteLookups = 0;
	$remoteBudgetReached = false;
	$accessLogResult = [
		'enabled' => false,
		'processed_lines' => 0,
		'matched_events' => 0,
		'updated_hits' => 0,
	];

	try {
		if ($hasIpQueue) {
			$selectStmt = db()->prepare(
				'SELECT ip_address, attempt_count
				 FROM pd_ip_enrichment_queue
				 WHERE next_attempt_at <= NOW()
				 ORDER BY last_seen_at DESC
				 LIMIT :limit'
			);

			$deleteStmt = db()->prepare('DELETE FROM pd_ip_enrichment_queue WHERE ip_address = :ip_address');
			$failStmt = db()->prepare(
				'UPDATE pd_ip_enrichment_queue
				 SET attempt_count = :attempt_count,
				     next_attempt_at = DATE_ADD(NOW(), INTERVAL :retry_seconds SECOND),
				     last_error = :last_error,
				     updated_at = NOW()
				 WHERE ip_address = :ip_address'
			);

			while ($processed < $maxRows && (microtime(true) - $startedAt) < $maxRuntimeSeconds) {
				$remaining = $maxRows - $processed;
				$selectStmt->bindValue(':limit', min(50, $remaining), PDO::PARAM_INT);
				$selectStmt->execute();
				$batch = $selectStmt->fetchAll();
				if (!$batch) {
					break;
				}

				foreach ($batch as $row) {
					if ($processed >= $maxRows || (microtime(true) - $startedAt) >= $maxRuntimeSeconds) {
						break;
					}

					if ($remoteLookups >= $maxRemoteLookups) {
						$remoteBudgetReached = true;
						break;
					}

					$processed++;
					$ipAddress = trim((string) ($row['ip_address'] ?? ''));
					$attempt = (int) ($row['attempt_count'] ?? 0) + 1;

					if ($ipAddress === '') {
						$failed++;
						continue;
					}

					$remoteLookups++;

					try {
						$enrichment = ensure_ip_enrichment($ipAddress, true);
						$source = (string) ($enrichment['source'] ?? 'unresolved');
						$resolvedHost = ensure_reverse_host_for_ip($ipAddress, true);
						if ($resolvedHost !== null && $resolvedHost !== '') {
							backfill_remote_host_for_ip_hits($ipAddress, $resolvedHost, 250);
						}
						if (auto_tag_ip_as_bot_if_confident($ipAddress)) {
							$autoBotTagged++;
						}

						if ($source !== 'unresolved') {
							$deleteStmt->execute(['ip_address' => $ipAddress]);
							$succeeded++;
							continue;
						}
					} catch (Throwable $e) {
					}

					$failed++;
					$retrySeconds = max(300, min(3600, (int) pow(2, min($attempt, 10))));
					$failStmt->bindValue(':attempt_count', $attempt, PDO::PARAM_INT);
					$failStmt->bindValue(':retry_seconds', $retrySeconds, PDO::PARAM_INT);
					$failStmt->bindValue(':last_error', 'lookup_failed', PDO::PARAM_STR);
					$failStmt->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
					$failStmt->execute();
				}

				if ($remoteBudgetReached) {
					break;
				}
			}
		}

		$elapsedSeconds = microtime(true) - $startedAt;
		$remainingSeconds = $maxRuntimeSeconds - $elapsedSeconds;
		$accessLogMaxLines = analytics_access_log_max_lines_per_run();
		if ($remainingSeconds <= 0.2) {
			$accessLogResult = [
				'enabled' => analytics_access_log_path() !== null,
				'processed_lines' => 0,
				'matched_events' => 0,
				'updated_hits' => 0,
				'skipped' => 'runtime_budget_exhausted',
			];
		} else {
			if ($remainingSeconds < 1.0) {
				$accessLogMaxLines = min($accessLogMaxLines, 300);
			}
			$accessLogResult = process_access_log_referrer_enrichment($accessLogMaxLines);
		}
	} catch (Throwable $e) {
		if (($accessLogResult['enabled'] ?? false) !== true) {
			try {
				$accessLogResult = process_access_log_referrer_enrichment(min(500, analytics_access_log_max_lines_per_run()));
			} catch (Throwable $inner) {
				$accessLogResult = [
					'enabled' => true,
					'processed_lines' => 0,
					'matched_events' => 0,
					'updated_hits' => 0,
					'error' => 'access_log_processing_failed',
				];
			}
		}
	} finally {
		$releaseStmt = db()->prepare('SELECT RELEASE_LOCK(:lock_name)');
		$releaseStmt->execute(['lock_name' => 'pixeldust_ip_enrichment_worker']);
	}

	return [
		'processed' => $processed,
		'succeeded' => $succeeded,
		'failed' => $failed,
		'auto_bot_tagged' => $autoBotTagged,
		'locked' => false,
		'access_log' => $accessLogResult,
	];
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
