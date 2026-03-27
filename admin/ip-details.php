<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

if (!is_installed()) {
	redirect('../install.php');
}

$token = trim((string) ($_GET['token'] ?? ''));
if ($token !== '' && !current_admin()) {
	$decoded = base64_decode($token, true);
	if ($decoded !== false && strpos($decoded, ':') !== false) {
		[$username, $password] = explode(':', $decoded, 2);
		$username = trim((string) $username);
		$password = (string) $password;

		if ($username !== '' && $password !== '') {
			$stmt = db()->prepare('SELECT id, password_hash FROM pd_admin_users WHERE username = :username LIMIT 1');
			$stmt->execute(['username' => $username]);
			$adminByToken = $stmt->fetch();

			if ($adminByToken && password_verify($password, (string) $adminByToken['password_hash'])) {
				$_SESSION['admin_user_id'] = (int) $adminByToken['id'];
			}
		}
	}
}

require_admin();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string) ($_POST['action'] ?? '') === 'save_ip_tag') {
	$postSourceType = trim((string) ($_POST['source_type'] ?? 'pixel'));
	if (!in_array($postSourceType, ['pixel', 'redirect'], true)) {
		$postSourceType = 'pixel';
	}

	$postPixelKey = trim((string) ($_POST['pixel_key'] ?? ''));
	$postRedirectKey = trim((string) ($_POST['redirect_key'] ?? ''));
	$postSourceKey = $postSourceType === 'redirect' ? $postRedirectKey : $postPixelKey;
	$postIpAddress = trim((string) ($_POST['ip'] ?? ''));
	if (strlen($postIpAddress) > 45) {
		$postIpAddress = substr($postIpAddress, 0, 45);
	}

	$postPeriod = (string) ($_POST['period'] ?? '7d');
	$postValidPeriods = ['24h', '7d', '30d'];
	if (!in_array($postPeriod, $postValidPeriods, true)) {
		$postPeriod = '7d';
	}

	$postTagValue = trim((string) ($_POST['operator_tag'] ?? ''));
	if (strlen($postTagValue) > 191) {
		$postTagValue = substr($postTagValue, 0, 191);
	}

	$redirectParams = [
		'source_type' => $postSourceType,
		'period' => $postPeriod,
		'ip' => $postIpAddress,
	];
	if ($postSourceType === 'redirect') {
		$redirectParams['redirect_key'] = $postSourceKey;
	} else {
		$redirectParams['pixel_key'] = $postSourceKey;
	}

	if ($postIpAddress === '' || filter_var($postIpAddress, FILTER_VALIDATE_IP) === false) {
		$redirectParams['tag_status'] = 'invalid_ip';
		redirect('ip-details.php?' . http_build_query($redirectParams));
	}

	try {
		$status = analytics_table_status();
		if (!(bool) ($status['ip_enrichment'] ?? false)) {
			$redirectParams['tag_status'] = 'migration_required';
			redirect('ip-details.php?' . http_build_query($redirectParams));
		}

		$saveStmt = db()->prepare(
			'INSERT INTO pd_ip_enrichment (ip_address, operator_tag, source, confidence, updated_at)
			 VALUES (:ip_address, :operator_tag, "operator", 1.000, NOW())
			 ON DUPLICATE KEY UPDATE
				operator_tag = VALUES(operator_tag),
				updated_at = NOW()'
		);
		$saveStmt->bindValue(':ip_address', $postIpAddress, PDO::PARAM_STR);
		if ($postTagValue === '') {
			$saveStmt->bindValue(':operator_tag', null, PDO::PARAM_NULL);
		} else {
			$saveStmt->bindValue(':operator_tag', $postTagValue, PDO::PARAM_STR);
		}
		$saveStmt->execute();
		$redirectParams['tag_status'] = 'saved';
	} catch (Throwable $e) {
		$redirectParams['tag_status'] = 'error';
	}

	redirect('ip-details.php?' . http_build_query($redirectParams));
}

$sourceType = trim((string) ($_GET['source_type'] ?? 'pixel'));
if (!in_array($sourceType, ['pixel', 'redirect'], true)) {
	$sourceType = 'pixel';
}

$pixelKey = trim((string) ($_GET['pixel_key'] ?? ''));
$redirectKey = trim((string) ($_GET['redirect_key'] ?? ''));
$sourceKey = $sourceType === 'redirect' ? $redirectKey : $pixelKey;
$ipAddress = trim((string) ($_GET['ip'] ?? ''));
$period = (string) ($_GET['period'] ?? '7d');
$tagStatus = trim((string) ($_GET['tag_status'] ?? ''));
$validPeriods = ['24h', '7d', '30d'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

if (strlen($ipAddress) > 45) {
	$ipAddress = substr($ipAddress, 0, 45);
}

$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');
$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
	->sub(new DateInterval($periodIntervalSpec))
	->format('Y-m-d H:i:s');

$hasRedirectTables = false;
try {
	$pdo = db();
	$hasRedirectTables = table_exists($pdo, 'pd_redirect_links') && table_exists($pdo, 'pd_redirect_hits');
} catch (Throwable $e) {
	$hasRedirectTables = false;
}

if ($sourceType === 'redirect' && !$hasRedirectTables) {
	$sourceType = 'pixel';
	$sourceKey = $pixelKey;
}

$pixels = db()->query('SELECT pixel_key, total_hits FROM pd_pixels ORDER BY pixel_key ASC')->fetchAll();
$redirects = [];
if ($hasRedirectTables) {
	$redirects = db()->query('SELECT redirect_key, total_hits FROM pd_redirect_links ORDER BY redirect_key ASC')->fetchAll();
}

$selectedSource = null;
if ($sourceKey !== '') {
	if ($sourceType === 'redirect') {
		$stmt = db()->prepare('SELECT id, redirect_key AS source_key, total_hits FROM pd_redirect_links WHERE redirect_key = :source_key LIMIT 1');
		$stmt->execute(['source_key' => $sourceKey]);
		$selectedSource = $stmt->fetch();
	} else {
		$stmt = db()->prepare('SELECT id, pixel_key AS source_key, total_hits FROM pd_pixels WHERE pixel_key = :source_key LIMIT 1');
		$stmt->execute(['source_key' => $sourceKey]);
		$selectedSource = $stmt->fetch();
	}
}

$tableStatus = analytics_table_status();
$summary = [
	'hits' => 0,
	'estimated_visits_balanced' => 0,
	'first_seen' => null,
	'last_seen' => null,
	'active_days' => 0,
	'unique_ref_domains' => 0,
	'unique_user_agents' => 0,
];
$geo = null;
$referrerRows = [];
$userAgentRows = [];
$timelineRows = [];
$clientRows = [];
$crossSourceRows = [];
$recentRows = [];
$ipOperatorTag = '';
$ipDisplayLabel = $ipAddress;

if ($ipAddress !== '' && filter_var($ipAddress, FILTER_VALIDATE_IP) !== false) {
	$singleIpTagMap = fetch_ip_operator_tags([$ipAddress]);
	$ipOperatorTag = trim((string) ($singleIpTagMap[$ipAddress] ?? ''));
	$ipDisplayLabel = format_ip_with_operator_tag($ipAddress, $ipOperatorTag);
}

if ($selectedSource && $ipAddress !== '') {
	$hitTable = $sourceType === 'redirect' ? 'pd_redirect_hits' : 'pd_pixel_hits';
	$idColumn = $sourceType === 'redirect' ? 'redirect_id' : 'pixel_id';
	$keyColumn = $sourceType === 'redirect' ? 'redirect_key' : 'pixel_key';
	$classTable = $sourceType === 'redirect' ? 'pd_redirect_hit_classification' : 'pd_hit_classification';
	$classAvailable = $sourceType === 'redirect' ? (bool) ($tableStatus['redirect_hit_classification'] ?? false) : (bool) ($tableStatus['hit_classification'] ?? false);

	if ($classAvailable) {
		$backfillSql =
			"SELECT h.id, h.$idColumn AS source_id, h.$keyColumn AS source_key, h.ip_address, h.user_agent, h.referrer, h.request_uri, h.accept_language, h.remote_host
			 FROM $hitTable h
			 LEFT JOIN $classTable c ON c.hit_id = h.id
			 WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND c.hit_id IS NULL
			 ORDER BY h.id DESC
			 LIMIT 120";
		$backfillStmt = db()->prepare($backfillSql);
		$backfillStmt->execute([
			'source_id' => (int) $selectedSource['id'],
			'ip_address' => $ipAddress,
		]);
		$backfillRows = $backfillStmt->fetchAll();
		foreach ($backfillRows as $row) {
			try {
				if ($sourceType === 'redirect') {
					classify_and_store_redirect_hit(
						(int) $row['id'],
						(int) $row['source_id'],
						(string) $row['source_key'],
						[
							'ip_address' => (string) ($row['ip_address'] ?? ''),
							'user_agent' => (string) ($row['user_agent'] ?? ''),
							'referrer' => (string) ($row['referrer'] ?? ''),
							'request_uri' => (string) ($row['request_uri'] ?? ''),
							'accept_language' => (string) ($row['accept_language'] ?? ''),
							'remote_host' => (string) ($row['remote_host'] ?? ''),
						],
						true
					);
				} else {
					classify_and_store_hit(
						(int) $row['id'],
						(int) $row['source_id'],
						(string) $row['source_key'],
						[
							'ip_address' => (string) ($row['ip_address'] ?? ''),
							'user_agent' => (string) ($row['user_agent'] ?? ''),
							'referrer' => (string) ($row['referrer'] ?? ''),
							'request_uri' => (string) ($row['request_uri'] ?? ''),
							'accept_language' => (string) ($row['accept_language'] ?? ''),
							'remote_host' => (string) ($row['remote_host'] ?? ''),
						],
						true
					);
				}
			} catch (Throwable $e) {
			}
		}
	}

	if ($tableStatus['ip_enrichment']) {
		try {
			$geo = ensure_ip_enrichment($ipAddress, true);
		} catch (Throwable $e) {
			$geo = null;
		}
		if ($ipOperatorTag === '') {
			$ipOperatorTag = trim((string) ($geo['operator_tag'] ?? ''));
			$ipDisplayLabel = format_ip_with_operator_tag($ipAddress, $ipOperatorTag);
		}
	}

	$referrerDomainExpr = "CASE WHEN h.referrer IS NULL OR TRIM(h.referrer)='' THEN '-' ELSE LOWER(SUBSTRING_INDEX(SUBSTRING_INDEX(TRIM(h.referrer),'://',-1),'/',1)) END";
	$emailCaseExpr = "CASE WHEN h.user_agent LIKE '%GoogleImageProxy%' OR h.remote_host LIKE 'google-proxy-%' OR h.referrer LIKE '%mobile-webview.gmail.com%' OR h.referrer LIKE '%mail.google.com%' THEN 'gmail' WHEN h.user_agent LIKE 'YahooMailProxy%' OR h.remote_host LIKE 'ec%.ycpi.%yahoo.com' THEN 'yahoo_mail' WHEN h.referrer LIKE '%outlook.live.com%' OR h.user_agent LIKE '%OneOutlook/%' OR h.user_agent LIKE '%ms-office%' THEN 'outlook_family' WHEN h.referrer LIKE '%webmail.%' OR h.referrer LIKE '%mail.%' OR h.referrer LIKE '%neo.space%' OR h.referrer LIKE '%titan.email%' THEN 'other_webmail' ELSE 'unknown' END";
	$clientExpr = $classAvailable ? "COALESCE(NULLIF(c.email_client_guess,''), $emailCaseExpr)" : $emailCaseExpr;
	$trafficExpr = $classAvailable ? "COALESCE(NULLIF(c.traffic_type,''), 'unknown')" : "CASE WHEN $clientExpr IN ('gmail','yahoo_mail') THEN 'proxy' ELSE 'unknown' END";
	$ispExpr = $classAvailable
		? "COALESCE(NULLIF(c.isp_guess,''), 'unknown')"
		: "CASE WHEN h.remote_host IS NULL OR TRIM(h.remote_host)='' THEN 'unknown' WHEN h.remote_host REGEXP '^[0-9]+(\\\\.[0-9]+){3}$' THEN 'ip_unresolved' ELSE LOWER(SUBSTRING_INDEX(TRIM(h.remote_host),'.',-2)) END";

	$summarySql =
		"SELECT
			COUNT(*) AS hits,
			MIN(h.hit_at) AS first_seen,
			MAX(h.hit_at) AS last_seen,
			COUNT(DISTINCT DATE(h.hit_at)) AS active_days,
			COUNT(DISTINCT $referrerDomainExpr) AS unique_ref_domains,
			COUNT(DISTINCT COALESCE(NULLIF(TRIM(h.user_agent),''),'-')) AS unique_user_agents
		 FROM $hitTable h
		 " . ($classAvailable ? "LEFT JOIN $classTable c ON c.hit_id = h.id" : '') . "
		 WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND h.hit_at >= :cutoff_utc";
	$summaryStmt = db()->prepare($summarySql);
	$summaryStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$summary = array_merge($summary, (array) $summaryStmt->fetch());

	$balancedVisitsSql =
		"WITH ordered_hits AS (
			SELECT
				h.hit_at,
				LAG(h.hit_at) OVER (
					PARTITION BY CONCAT(COALESCE(h.ip_address, ''), '|', MD5(CONCAT(COALESCE(h.user_agent, ''), '|', COALESCE(h.accept_language, ''))))
					ORDER BY h.hit_at
				) AS prev_hit
			FROM $hitTable h
			WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND h.hit_at >= :cutoff_utc
		)
		SELECT COALESCE(SUM(CASE WHEN prev_hit IS NULL OR TIMESTAMPDIFF(MINUTE, prev_hit, hit_at) > 30 THEN 1 ELSE 0 END), 0) AS estimated_visits_balanced
		FROM ordered_hits";
	$balancedVisitsStmt = db()->prepare($balancedVisitsSql);
	$balancedVisitsStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$balancedVisitsRow = (array) $balancedVisitsStmt->fetch();
	$summary['estimated_visits_balanced'] = (int) ($balancedVisitsRow['estimated_visits_balanced'] ?? 0);

	$timelineSql =
		"SELECT DATE(h.hit_at) AS bucket, COUNT(*) AS hits
		 FROM $hitTable h
		 WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND h.hit_at >= :cutoff_utc
		 GROUP BY bucket
		 ORDER BY bucket ASC";
	$timelineStmt = db()->prepare($timelineSql);
	$timelineStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$timelineRows = $timelineStmt->fetchAll();

	$refSql =
		"SELECT $referrerDomainExpr AS ref_domain, COUNT(*) AS hits
		 FROM $hitTable h
		 WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND h.hit_at >= :cutoff_utc
		 GROUP BY ref_domain
		 ORDER BY hits DESC
		 LIMIT 10";
	$refStmt = db()->prepare($refSql);
	$refStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$referrerRows = $refStmt->fetchAll();

	$uaSql =
		"SELECT COALESCE(NULLIF(TRIM(h.user_agent),''),'-') AS user_agent, COUNT(*) AS hits
		 FROM $hitTable h
		 WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND h.hit_at >= :cutoff_utc
		 GROUP BY user_agent
		 ORDER BY hits DESC
		 LIMIT 10";
	$uaStmt = db()->prepare($uaSql);
	$uaStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$userAgentRows = $uaStmt->fetchAll();

	$clientSql =
		"SELECT $clientExpr AS client_name, $trafficExpr AS traffic_type, $ispExpr AS isp_name, COUNT(*) AS hits
		 FROM $hitTable h
		 " . ($classAvailable ? "LEFT JOIN $classTable c ON c.hit_id = h.id" : '') . "
		 WHERE h.$idColumn = :source_id AND h.ip_address = :ip_address AND h.hit_at >= :cutoff_utc
		 GROUP BY client_name, traffic_type, isp_name
		 ORDER BY hits DESC";
	$clientStmt = db()->prepare($clientSql);
	$clientStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$clientRows = $clientStmt->fetchAll();

	$crossSql =
		"SELECT $keyColumn AS source_key, COUNT(*) AS hits, MIN(hit_at) AS first_seen, MAX(hit_at) AS last_seen
		 FROM $hitTable
		 WHERE ip_address = :ip_address
		 GROUP BY $keyColumn
		 ORDER BY hits DESC
		 LIMIT 15";
	$crossStmt = db()->prepare($crossSql);
	$crossStmt->execute(['ip_address' => $ipAddress]);
	$crossSourceRows = $crossStmt->fetchAll();

	$recentSql =
		"SELECT hit_at, referrer, user_agent, remote_host
		 FROM $hitTable
		 WHERE $idColumn = :source_id AND ip_address = :ip_address AND hit_at >= :cutoff_utc
		 ORDER BY hit_at DESC
		 LIMIT 100";
	$recentStmt = db()->prepare($recentSql);
	$recentStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'ip_address' => $ipAddress,
		'cutoff_utc' => $cutoffUtc,
	]);
	$recentRows = $recentStmt->fetchAll();
}

$displayName = $sourceType === 'redirect' ? 'Redirect IP Drilldown' : 'IP Drilldown';

render_header('IP Drilldown');
?>
<div class="spaced card">
	<div>
		<h1><?php echo e($displayName); ?></h1>
		<p class="muted">Analyze one IP address within a source and across that source type.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="analytics.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode($sourceKey) : '&pixel_key=' . urlencode($sourceKey); ?>&period=<?php echo urlencode($period); ?>">Back to analytics</a>
		<a class="nav-btn" href="stats.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode($sourceKey) : '&pixel_key=' . urlencode($sourceKey); ?>&period=<?php echo urlencode($period); ?>">Back to stats</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if (!$hasRedirectTables): ?>
	<div class="error">Redirect analytics tables not migrated yet. Run <a href="../migrate.php">migrations</a> to enable redirect drilldown.</div>
<?php endif; ?>

<div class="card">
	<form method="get" class="row">
		<div>
			<label>Source Type</label>
			<select name="source_type">
				<option value="pixel" <?php echo $sourceType === 'pixel' ? 'selected' : ''; ?>>Pixel</option>
				<option value="redirect" <?php echo $sourceType === 'redirect' ? 'selected' : ''; ?>>Redirect URL</option>
			</select>
		</div>
		<div>
			<label><?php echo $sourceType === 'redirect' ? 'Redirect ID' : 'Pixel ID'; ?></label>
			<?php if ($sourceType === 'redirect'): ?>
				<select name="redirect_key">
					<option value="">Select redirect</option>
					<?php foreach ($redirects as $redirect): ?>
						<option value="<?php echo e((string) $redirect['redirect_key']); ?>" <?php echo $sourceKey === (string) $redirect['redirect_key'] ? 'selected' : ''; ?>><?php echo e((string) $redirect['redirect_key']); ?> (<?php echo e((string) $redirect['total_hits']); ?>)</option>
					<?php endforeach; ?>
				</select>
			<?php else: ?>
				<select name="pixel_key">
					<option value="">Select pixel</option>
					<?php foreach ($pixels as $pixel): ?>
						<option value="<?php echo e((string) $pixel['pixel_key']); ?>" <?php echo $sourceKey === (string) $pixel['pixel_key'] ? 'selected' : ''; ?>><?php echo e((string) $pixel['pixel_key']); ?> (<?php echo e((string) $pixel['total_hits']); ?>)</option>
					<?php endforeach; ?>
				</select>
			<?php endif; ?>
		</div>
		<div>
			<label>IP Address</label>
			<input type="text" name="ip" value="<?php echo e($ipAddress); ?>" placeholder="74.125.215.2" maxlength="45">
		</div>
		<div>
			<label>Period</label>
			<select name="period">
				<?php foreach ($validPeriods as $opt): ?>
					<option value="<?php echo e($opt); ?>" <?php echo $period === $opt ? 'selected' : ''; ?>><?php echo e($opt); ?></option>
				<?php endforeach; ?>
			</select>
		</div>
		<div style="align-self:end;"><button type="submit">Load IP Details</button></div>
	</form>
</div>

<?php if ($sourceKey !== '' && !$selectedSource): ?>
	<div class="error"><?php echo e($sourceType === 'redirect' ? 'Redirect not found.' : 'Pixel not found.'); ?></div>
<?php endif; ?>

<?php if ($selectedSource && $ipAddress === ''): ?>
	<div class="error">Enter an IP address to load details.</div>
<?php endif; ?>

<?php if ($tagStatus === 'saved'): ?>
	<div class="card"><p class="muted">IP tag updated.</p></div>
<?php elseif ($tagStatus === 'invalid_ip'): ?>
	<div class="error">Invalid IP address. Tag was not saved.</div>
<?php elseif ($tagStatus === 'migration_required'): ?>
	<div class="error">IP enrichment table is missing. Run <a href="../migrate.php">migrations</a> to enable IP tags.</div>
<?php elseif ($tagStatus === 'error'): ?>
	<div class="error">Unable to save IP tag right now. Please try again.</div>
<?php endif; ?>

<?php if ($selectedSource && $ipAddress !== ''): ?>
	<div class="card">
		<h2>IP: <?php echo e($ipDisplayLabel); ?></h2>
		<p class="muted">Source: <?php echo e((string) $selectedSource['source_key']); ?> | Period: <?php echo e($period); ?> | UTC Window start: <?php echo e($cutoffUtc); ?></p>
	</div>

	<div class="row">
		<div class="card"><h3>Hits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['hits'] ?? 0))); ?></p></div>
		<div class="card"><h3>Active Days</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['active_days'] ?? 0))); ?></p></div>
		<div class="card"><h3>Estimated Visits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['estimated_visits_balanced'] ?? 0))); ?></p></div>
		<div class="card"><h3>User Agent Variants</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['unique_user_agents'] ?? 0))); ?></p></div>
	</div>

	<div class="card">
		<h3>First/Last Seen</h3>
		<p class="muted">First: <?php echo e(format_db_datetime((string) ($summary['first_seen'] ?? ''), 'Y-m-d H:i:s', '-')); ?> | Last: <?php echo e(format_db_datetime((string) ($summary['last_seen'] ?? ''), 'Y-m-d H:i:s', '-')); ?> (<?php echo e(app_timezone_name()); ?>)</p>
	</div>

	<div class="row">
		<div class="card">
			<h3>Geo / Network</h3>
			<table>
				<tbody>
				<tr><th>Country</th><td><?php echo e((string) ($geo['country_code'] ?? '-')); ?></td></tr>
				<tr><th>Region</th><td><?php echo e((string) ($geo['region'] ?? '-')); ?></td></tr>
				<tr><th>City</th><td><?php echo e((string) ($geo['city'] ?? '-')); ?></td></tr>
				<tr><th>ASN</th><td><?php echo e((string) ($geo['asn'] ?? '-')); ?></td></tr>
				<tr><th>ASN Org</th><td><?php echo e((string) ($geo['asn_org'] ?? '-')); ?></td></tr>
				<tr><th>ISP</th><td><?php echo e((string) ($geo['isp_name'] ?? '-')); ?></td></tr>
				<tr><th>Proxy</th><td><?php echo ((int) ($geo['is_proxy'] ?? 0) === 1) ? 'Yes' : 'No'; ?></td></tr>
				<tr><th>Hosting</th><td><?php echo ((int) ($geo['is_hosting'] ?? 0) === 1) ? 'Yes' : 'No'; ?></td></tr>
				<tr><th>Source</th><td><?php echo e((string) ($geo['source'] ?? '-')); ?></td></tr>
				<tr>
					<th>Tag</th>
					<td>
						<form method="post" class="inline" style="gap:8px;align-items:center;flex-wrap:wrap;">
							<input type="hidden" name="action" value="save_ip_tag">
							<input type="hidden" name="source_type" value="<?php echo e($sourceType); ?>">
							<?php if ($sourceType === 'redirect'): ?>
								<input type="hidden" name="redirect_key" value="<?php echo e((string) $selectedSource['source_key']); ?>">
							<?php else: ?>
								<input type="hidden" name="pixel_key" value="<?php echo e((string) $selectedSource['source_key']); ?>">
							<?php endif; ?>
							<input type="hidden" name="ip" value="<?php echo e($ipAddress); ?>">
							<input type="hidden" name="period" value="<?php echo e($period); ?>">
							<input type="text" name="operator_tag" value="<?php echo e($ipOperatorTag); ?>" maxlength="191" placeholder="Example: Levi" style="width:220px;max-width:100%;">
							<button type="submit">Save</button>
						</form>
					</td>
				</tr>
				</tbody>
			</table>
		</div>

		<div class="card">
			<h3>Client / Traffic / ISP Mix</h3>
			<table>
				<thead><tr><th>Client</th><th>Traffic</th><th>ISP</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$clientRows): ?>
					<tr><td colspan="4" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($clientRows as $row): ?>
						<tr><td><?php echo e((string) ($row['client_name'] ?? 'unknown')); ?></td><td><?php echo e((string) ($row['traffic_type'] ?? 'unknown')); ?></td><td><?php echo e((string) ($row['isp_name'] ?? 'unknown')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="row">
		<div class="card">
			<h3>Top Referrers</h3>
			<table>
				<thead><tr><th>Referrer Domain</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$referrerRows): ?>
					<tr><td colspan="2" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($referrerRows as $row): ?>
						<tr><td><?php echo e((string) ($row['ref_domain'] ?? '-')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>

		<div class="card">
			<h3>User Agents</h3>
			<table>
				<thead><tr><th>User Agent</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$userAgentRows): ?>
					<tr><td colspan="2" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($userAgentRows as $row): ?>
						<tr><td><?php echo e((string) ($row['user_agent'] ?? '-')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="card">
		<h3>Hits by Day</h3>
		<table>
			<thead><tr><th>Day (UTC)</th><th>Hits</th></tr></thead>
			<tbody>
			<?php if (!$timelineRows): ?>
				<tr><td colspan="2" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($timelineRows as $row): ?>
					<tr><td><?php echo e((string) ($row['bucket'] ?? '-')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td></tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>

	<div class="card">
		<h3>Cross-Source Activity for this IP</h3>
		<table>
			<thead><tr><th>Source Key</th><th>Hits</th><th>First Seen</th><th>Last Seen</th><th>Open</th></tr></thead>
			<tbody>
			<?php if (!$crossSourceRows): ?>
				<tr><td colspan="5" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($crossSourceRows as $row): ?>
						<?php
						$crossSourceKey = (string) ($row['source_key'] ?? '');
						$crossSourceStatsParams = [
							'source_type' => $sourceType,
							'period' => $period,
						];
						if ($sourceType === 'redirect') {
							$crossSourceStatsParams['redirect_key'] = $crossSourceKey;
						} else {
							$crossSourceStatsParams['pixel_key'] = $crossSourceKey;
						}
						$crossSourceStatsHref = 'stats.php?' . http_build_query($crossSourceStatsParams);
						?>
					<tr>
							<td><a href="<?php echo e($crossSourceStatsHref); ?>"><?php echo e($crossSourceKey); ?></a></td>
						<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
						<td><?php echo e(format_db_datetime((string) ($row['first_seen'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td><?php echo e(format_db_datetime((string) ($row['last_seen'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td><a href="ip-details.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode((string) ($row['source_key'] ?? '')) : '&pixel_key=' . urlencode((string) ($row['source_key'] ?? '')); ?>&ip=<?php echo urlencode($ipAddress); ?>&period=<?php echo urlencode($period); ?>">Open</a></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>

	<div class="card">
		<h3>Recent Hits</h3>
		<table>
			<thead><tr><th>Date/Time</th><th>Referrer</th><th>User Agent</th><th>Remote Host</th></tr></thead>
			<tbody>
			<?php if (!$recentRows): ?>
				<tr><td colspan="4" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($recentRows as $row): ?>
					<tr>
						<td><?php echo e(format_db_datetime((string) ($row['hit_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td><?php echo e((string) (($row['referrer'] ?? '') !== '' ? $row['referrer'] : '-')); ?></td>
						<td><?php echo e((string) (($row['user_agent'] ?? '') !== '' ? $row['user_agent'] : '-')); ?></td>
						<td><?php echo e((string) (($row['remote_host'] ?? '') !== '' ? $row['remote_host'] : '-')); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
<?php endif; ?>
<?php
render_footer();
