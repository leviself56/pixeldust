<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

function normalize_ref_fallback(string $value): string {
	$value = trim($value);
	if ($value === '') {
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

	return substr($value, 0, 255);
}

if (!is_installed()) {
	http_response_code(503);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Pixel Dust not installed.';
	exit;
}

$redirectKey = trim((string) ($_GET['id'] ?? ''));
$redirectKey = sanitize_redirect_key($redirectKey);
if ($redirectKey === '') {
	http_response_code(400);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Invalid redirect id.';
	exit;
}

$explicitTriggerId = trim((string) ($_GET['trigger'] ?? ''));
if ($explicitTriggerId === '') {
	$explicitTriggerId = trim((string) ($_GET['trigger_id'] ?? ''));
}

$stmt = db()->prepare(
	'SELECT id, redirect_key, destination_url, is_active
	 FROM pd_redirect_links
	 WHERE redirect_key = :redirect_key
	 LIMIT 1'
);
$stmt->execute(['redirect_key' => $redirectKey]);
$redirect = $stmt->fetch();

if (!$redirect) {
	http_response_code(404);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Redirect not found.';
	exit;
}

if ((int) ($redirect['is_active'] ?? 0) !== 1) {
	http_response_code(410);
	header('Content-Type: text/html; charset=utf-8');
	echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Broken Link</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:#f5f7fb;color:#1f2937;margin:0;padding:32px;display:flex;min-height:100vh;align-items:center;justify-content:center}.card{background:#fff;max-width:560px;width:100%;border:1px solid #dbe3ef;border-radius:12px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.08)}h1{margin:0 0 10px;font-size:28px;line-height:1.2}.muted{margin:0;color:#4b5563;line-height:1.5}.tag{display:inline-block;margin-bottom:12px;padding:4px 10px;border-radius:999px;background:#ffe9e9;color:#9f1239;font-size:12px;font-weight:700;letter-spacing:.02em;text-transform:uppercase}</style></head><body><main class="card"><div class="tag">Broken Link</div><h1>This link is no longer active.</h1><p class="muted">This URL has been disabled or removed.<br />Please contact the sender and ask for an updated link.</p></main></body></html>';
	exit;
}

$destinationUrl = trim((string) ($redirect['destination_url'] ?? ''));
if ($destinationUrl === '' || !filter_var($destinationUrl, FILTER_VALIDATE_URL)) {
	http_response_code(500);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Redirect destination invalid.';
	exit;
}

$scheme = strtolower((string) parse_url($destinationUrl, PHP_URL_SCHEME));
if (!in_array($scheme, ['http', 'https'], true)) {
	http_response_code(500);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Redirect scheme invalid.';
	exit;
}

$ipAddress = substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
$userAgent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
$referrer = trim((string) ($_SERVER['HTTP_REFERER'] ?? ''));
if ($referrer === '') {
	$referrer = normalize_ref_fallback((string) ($_GET['ref'] ?? ''));
}
$requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '');
$queryString = (string) ($_SERVER['QUERY_STRING'] ?? '');
$acceptLanguage = substr((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''), 0, 255);
$remoteHost = substr((string) @gethostbyaddr($ipAddress), 0, 255);

$insertHit = db()->prepare(
	'INSERT INTO pd_redirect_hits (
		redirect_id, redirect_key, hit_at, ip_address, user_agent, referrer, request_uri, query_string,
		accept_language, remote_host, trigger_id_used, destination_url_at_hit
	 ) VALUES (
		:redirect_id, :redirect_key, NOW(), :ip_address, :user_agent, :referrer, :request_uri, :query_string,
		:accept_language, :remote_host, :trigger_id_used, :destination_url_at_hit
	 )'
);

$insertHit->execute([
	'redirect_id' => (int) $redirect['id'],
	'redirect_key' => (string) $redirect['redirect_key'],
	'ip_address' => $ipAddress,
	'user_agent' => $userAgent,
	'referrer' => $referrer,
	'request_uri' => $requestUri,
	'query_string' => $queryString,
	'accept_language' => $acceptLanguage,
	'remote_host' => $remoteHost,
	'trigger_id_used' => $explicitTriggerId !== '' ? $explicitTriggerId : null,
	'destination_url_at_hit' => $destinationUrl,
]);

$hitId = (int) db()->lastInsertId();

$update = db()->prepare('UPDATE pd_redirect_links SET total_hits = total_hits + 1, updated_at = NOW() WHERE id = :id');
$update->execute(['id' => (int) $redirect['id']]);

try {
	fire_pixel_triggers((string) $redirect['redirect_key'], (int) $redirect['id'], $hitId, [
		'hit_at' => date('Y-m-d H:i:s'),
		'ip_address' => $ipAddress,
		'user_agent' => $userAgent,
		'referrer' => $referrer,
		'request_uri' => $requestUri,
		'query_string' => $queryString,
		'accept_language' => $acceptLanguage,
		'remote_host' => $remoteHost,
	], $explicitTriggerId !== '' ? $explicitTriggerId : null);
} catch (Throwable $e) {
}

try {
	classify_and_store_redirect_hit($hitId, (int) $redirect['id'], (string) $redirect['redirect_key'], [
		'ip_address' => $ipAddress,
		'user_agent' => $userAgent,
		'referrer' => $referrer,
		'request_uri' => $requestUri,
		'accept_language' => $acceptLanguage,
		'remote_host' => $remoteHost,
	], false);
} catch (Throwable $e) {
}

try {
	enqueue_ip_for_enrichment($ipAddress);
	try_start_ip_enrichment_worker(30);
} catch (Throwable $e) {
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Location: ' . $destinationUrl, true, 302);
exit;
