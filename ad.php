<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

header('Content-Type: application/javascript; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$adKey = sanitize_ad_key((string) ($_GET['id'] ?? ''));
if ($adKey === '') {
	echo "/* ad.js: missing id */\n";
	exit;
}

try {
	$stmt = db()->prepare(
		'SELECT id, ad_key, rule_name, priority, match_conditions, custom_js, action_type, action_value, run_once_enabled, run_once_period_seconds, trigger_on_match, trigger_id
		 FROM pd_ad_rules
		 WHERE ad_key = :ad_key AND is_active = 1
		 ORDER BY priority ASC, id ASC'
	);
	$stmt->execute(['ad_key' => $adKey]);
	$rules = $stmt->fetchAll();
} catch (Throwable $e) {
	echo "/* ad.js: rules unavailable */\n";
	exit;
}

if (!$rules) {
	echo "/* ad.js: no active rules for id */\n";
	exit;
}

$ipAddress = substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
$userAgent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
$referrer = (string) ($_SERVER['HTTP_REFERER'] ?? '');
$requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '');
$queryString = (string) ($_SERVER['QUERY_STRING'] ?? '');
$acceptLanguage = substr((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''), 0, 255);
$remoteHost = substr((string) ($_SERVER['REMOTE_HOST'] ?? ''), 0, 255);

$enrichment = [];
if ($ipAddress !== '' && filter_var($ipAddress, FILTER_VALIDATE_IP) !== false) {
	try {
		$enrichment = ensure_ip_enrichment($ipAddress, false);
	} catch (Throwable $e) {
		$enrichment = [];
	}
}

$emailGuess = infer_email_client([
	'user_agent' => $userAgent,
	'referrer' => $referrer,
	'remote_host' => $remoteHost,
]);
$trafficType = infer_traffic_type([
	'ip_address' => $ipAddress,
	'user_agent' => $userAgent,
	'referrer' => $referrer,
	'request_uri' => $requestUri,
	'query_string' => $queryString,
	'accept_language' => $acceptLanguage,
	'remote_host' => $remoteHost,
], $enrichment, (string) ($emailGuess['client'] ?? 'unknown'));

$context = [
	'traffic_type' => $trafficType,
	'user_agent' => trim($userAgent),
	'ip_address' => $ipAddress,
	'operator_tag' => trim((string) ($enrichment['operator_tag'] ?? '')),
	'country_code' => strtoupper(trim((string) ($enrichment['country_code'] ?? ''))),
	'region' => trim((string) ($enrichment['region'] ?? '')),
	'city' => trim((string) ($enrichment['city'] ?? '')),
	'asn' => trim((string) ($enrichment['asn'] ?? '')),
	'asn_org' => trim((string) ($enrichment['asn_org'] ?? '')),
	'isp_name' => trim((string) ($enrichment['isp_name'] ?? '')),
	'reverse_host' => trim((string) (($enrichment['reverse_host'] ?? '') !== '' ? $enrichment['reverse_host'] : $remoteHost)),
];

$matchedRule = null;
$matchedScript = '';

foreach ($rules as $rule) {
	$conditions = decode_ad_match_conditions((string) ($rule['match_conditions'] ?? ''));
	if (!ad_rule_matches_context($conditions, $context)) {
		continue;
	}

	$ruleId = (int) ($rule['id'] ?? 0);
	$runOnceEnabled = (int) ($rule['run_once_enabled'] ?? 0) === 1;
	$runOncePeriodSeconds = (int) ($rule['run_once_period_seconds'] ?? 0);
	if ($runOnceEnabled && $runOncePeriodSeconds > 0 && $ruleId > 0) {
		try {
			$cutoff = (new DateTimeImmutable('now', app_timezone_object()))
				->sub(new DateInterval('PT' . $runOncePeriodSeconds . 'S'))
				->format('Y-m-d H:i:s');

			$existingMatchStmt = db()->prepare(
				'SELECT id
				 FROM pd_ad_hit_logs
				 WHERE matched = 1
				   AND matched_rule_id = :rule_id
				   AND ip_address = :ip_address
				   AND user_agent = :user_agent
				   AND hit_at >= :cutoff
				 ORDER BY id DESC
				 LIMIT 1'
			);
			$existingMatchStmt->execute([
				'rule_id' => $ruleId,
				'ip_address' => $ipAddress,
				'user_agent' => $userAgent,
				'cutoff' => $cutoff,
			]);
			if ($existingMatchStmt->fetch()) {
				continue;
			}
		} catch (Throwable $e) {
		}
	}

	$script = render_ad_rule_javascript(
		(string) ($rule['action_type'] ?? 'custom_js'),
		(string) ($rule['action_value'] ?? ''),
		(string) ($rule['custom_js'] ?? '')
	);

	if ((int) ($rule['trigger_on_match'] ?? 0) === 1 && trim((string) ($rule['trigger_id'] ?? '')) !== '') {
		try {
			fire_trigger_action_by_id((string) $rule['trigger_id'], [
				'event' => 'ad_match',
				'ad_id' => (string) ($rule['ad_key'] ?? $adKey),
				'ad_rule_id' => $ruleId,
				'ad_priority' => (int) ($rule['priority'] ?? 0),
				'hit_at' => date('Y-m-d H:i:s'),
				'ip_address' => $ipAddress,
				'user_agent' => $userAgent,
				'referrer' => $referrer,
				'query_string' => $queryString,
				'country_code' => (string) ($context['country_code'] ?? ''),
			]);
		} catch (Throwable $e) {
		}
	}

	$matchedRule = $rule;
	$matchedScript = $script;
	break;
}

try {
	$logStmt = db()->prepare(
		'INSERT INTO pd_ad_hit_logs
		 (ad_key, hit_at, ip_address, user_agent, referrer, request_uri, query_string, accept_language, remote_host, traffic_type, operator_tag, country_code, region, city, asn, asn_org, isp_name, reverse_host, matched, matched_rule_id, matched_rule_name, matched_action_type, created_at)
		 VALUES
		 (:ad_key, :hit_at, :ip_address, :user_agent, :referrer, :request_uri, :query_string, :accept_language, :remote_host, :traffic_type, :operator_tag, :country_code, :region, :city, :asn, :asn_org, :isp_name, :reverse_host, :matched, :matched_rule_id, :matched_rule_name, :matched_action_type, :created_at)'
	);
	$hitAt = date('Y-m-d H:i:s');
	$logStmt->execute([
		'ad_key' => $adKey,
		'hit_at' => $hitAt,
		'ip_address' => $ipAddress,
		'user_agent' => $userAgent,
		'referrer' => $referrer,
		'request_uri' => $requestUri,
		'query_string' => $queryString,
		'accept_language' => $acceptLanguage,
		'remote_host' => $remoteHost,
		'traffic_type' => (string) ($context['traffic_type'] ?? 'unknown'),
		'operator_tag' => (string) ($context['operator_tag'] ?? '') !== '' ? (string) $context['operator_tag'] : null,
		'country_code' => (string) ($context['country_code'] ?? '') !== '' ? (string) $context['country_code'] : null,
		'region' => (string) ($context['region'] ?? '') !== '' ? (string) $context['region'] : null,
		'city' => (string) ($context['city'] ?? '') !== '' ? (string) $context['city'] : null,
		'asn' => (string) ($context['asn'] ?? '') !== '' ? (string) $context['asn'] : null,
		'asn_org' => (string) ($context['asn_org'] ?? '') !== '' ? (string) $context['asn_org'] : null,
		'isp_name' => (string) ($context['isp_name'] ?? '') !== '' ? (string) $context['isp_name'] : null,
		'reverse_host' => (string) ($context['reverse_host'] ?? '') !== '' ? (string) $context['reverse_host'] : null,
		'matched' => $matchedRule ? 1 : 0,
		'matched_rule_id' => $matchedRule ? (int) ($matchedRule['id'] ?? 0) : null,
		'matched_rule_name' => $matchedRule ? (string) ($matchedRule['rule_name'] ?? '') : null,
		'matched_action_type' => $matchedRule ? (string) ($matchedRule['action_type'] ?? '') : null,
		'created_at' => $hitAt,
	]);
} catch (Throwable $e) {
}

try {
	if ($ipAddress !== '') {
		enqueue_ip_for_enrichment($ipAddress);
	}
	try_start_ip_enrichment_worker(30);
} catch (Throwable $e) {
}

if ($matchedRule) {
	echo $matchedScript . "\n";
	exit;
}

echo "/* ad.js: no matching rules */\n";
