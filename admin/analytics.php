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

function render_simple_svg_chart(array $rows, string $valueKey = 'hits'): string
{
	if (!$rows) {
		return '<p class="muted">No data in selected period.</p>';
	}

	$width = 900;
	$height = 280;
	$padding = 36;
	$usableWidth = $width - ($padding * 2);
	$usableHeight = $height - ($padding * 2);

	$values = array_map(static fn($row): int => (int) ($row[$valueKey] ?? 0), $rows);
	$maxValue = max($values);
	if ($maxValue < 1) {
		$maxValue = 1;
	}

	$countRows = count($rows);
	$points = [];
	$labels = [];

	foreach ($rows as $index => $row) {
		$x = $padding + (($countRows <= 1 ? 0 : $index / ($countRows - 1)) * $usableWidth);
		$y = $height - $padding - (((int) ($row[$valueKey] ?? 0) / $maxValue) * $usableHeight);
		$points[] = round($x, 2) . ',' . round($y, 2);
		$labels[] = [
			'x' => $x,
			'y' => $height - ($padding - 14),
			'text' => substr((string) ($row['bucket'] ?? ''), 5),
		];
	}

	$svg = '<svg viewBox="0 0 ' . $width . ' ' . $height . '" width="100%" height="280" role="img">';
	$svg .= '<line x1="' . $padding . '" y1="' . ($height - $padding) . '" x2="' . ($width - $padding) . '" y2="' . ($height - $padding) . '" stroke="#ccc" />';
	$svg .= '<line x1="' . $padding . '" y1="' . $padding . '" x2="' . $padding . '" y2="' . ($height - $padding) . '" stroke="#ccc" />';
	$svg .= '<polyline fill="none" stroke="#1f4ea5" stroke-width="2" points="' . implode(' ', $points) . '" />';

	foreach ($points as $point) {
		[$cx, $cy] = explode(',', $point);
		$svg .= '<circle cx="' . $cx . '" cy="' . $cy . '" r="3" fill="#1f4ea5" />';
	}

	foreach ($labels as $label) {
		$svg .= '<text x="' . round((float) $label['x'], 2) . '" y="' . round((float) $label['y'], 2) . '" text-anchor="middle" font-size="10" fill="#666">' . e((string) $label['text']) . '</text>';
	}

	$svg .= '<text x="' . ($padding + 4) . '" y="' . ($padding + 10) . '" font-size="10" fill="#666">Max: ' . $maxValue . '</text>';
	$svg .= '</svg>';

	return $svg;
}

$sourceType = trim((string) ($_GET['source_type'] ?? 'pixel'));
if (!in_array($sourceType, ['pixel', 'redirect'], true)) {
	$sourceType = 'pixel';
}

$pixelKey = trim((string) ($_GET['pixel_key'] ?? ''));
$redirectKey = trim((string) ($_GET['redirect_key'] ?? ''));
$sourceKey = $sourceType === 'redirect' ? $redirectKey : $pixelKey;
$period = (string) ($_GET['period'] ?? '7d');
$heatmapMetric = trim((string) ($_GET['heatmap_metric'] ?? 'estimated_visits'));
$validHeatmapMetrics = ['hits', 'estimated_visits'];
if (!in_array($heatmapMetric, $validHeatmapMetrics, true)) {
	$heatmapMetric = 'hits';
}
$validPeriods = ['24h', '7d', '30d'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');
$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
	->sub(new DateInterval($periodIntervalSpec))
	->format('Y-m-d H:i:s');
$appTimezoneName = app_timezone_name();
$appTimezoneOffsetMinutes = (int) floor((new DateTimeImmutable('now', app_timezone_object()))->getOffset() / 60);

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

$pixels = db()->query('SELECT id, pixel_key, total_hits FROM pd_pixels ORDER BY pixel_key ASC')->fetchAll();
$redirects = [];
if ($hasRedirectTables) {
	$redirects = db()->query('SELECT id, redirect_key, total_hits FROM pd_redirect_links ORDER BY redirect_key ASC')->fetchAll();
}
$selectedSource = null;

if ($sourceKey !== '') {
	if ($sourceType === 'redirect') {
		$stmt = db()->prepare('SELECT id, redirect_key AS source_key, total_hits, created_at FROM pd_redirect_links WHERE redirect_key = :source_key LIMIT 1');
		$stmt->execute(['source_key' => $sourceKey]);
		$selectedSource = $stmt->fetch();
	} else {
		$stmt = db()->prepare('SELECT id, pixel_key AS source_key, total_hits, created_at FROM pd_pixels WHERE pixel_key = :source_key LIMIT 1');
		$stmt->execute(['source_key' => $sourceKey]);
		$selectedSource = $stmt->fetch();
	}
}

$tableStatus = analytics_table_status();
$summary = [
	'total_hits' => 0,
	'unique_ips' => 0,
	'estimated_visits_balanced' => 0,
	'unique_referrers' => 0,
	'proxy_hits' => 0,
	'human_hits' => 0,
];
$topReferrers = [];
$topIsps = [];
$topCountries = [];
$clientMix = [];
$timelineRows = [];
$topIps = [];
$heatmapRows = [];
$heatmapGrid = [];
$heatmapMaxHits = 0;
$heatmapWeekdayLabels = [
	1 => 'Sun',
	2 => 'Mon',
	3 => 'Tue',
	4 => 'Wed',
	5 => 'Thu',
	6 => 'Fri',
	7 => 'Sat',
];

if ($selectedSource) {
	if ($sourceType === 'redirect' && $tableStatus['redirect_hit_classification']) {
		try {
			backfill_hit_classification_for_redirect((int) $selectedSource['id'], 80, true);
		} catch (Throwable $e) {
		}
	}
	if ($sourceType === 'pixel' && $tableStatus['hit_classification']) {
		try {
			backfill_hit_classification_for_pixel((int) $selectedSource['id'], 80, true);
		} catch (Throwable $e) {
		}
	}

	$hitTable = $sourceType === 'redirect' ? 'pd_redirect_hits' : 'pd_pixel_hits';
	$idColumn = $sourceType === 'redirect' ? 'redirect_id' : 'pixel_id';
	$classificationTable = $sourceType === 'redirect' ? 'pd_redirect_hit_classification' : 'pd_hit_classification';
	$classificationAvailable = $sourceType === 'redirect' ? (bool) $tableStatus['redirect_hit_classification'] : (bool) $tableStatus['hit_classification'];

	$referrerDomainExpr = "CASE WHEN h.referrer IS NULL OR TRIM(h.referrer)='' THEN '-' ELSE LOWER(SUBSTRING_INDEX(SUBSTRING_INDEX(TRIM(h.referrer),'://',-1),'/',1)) END";
	$emailCaseExpr = "CASE WHEN h.user_agent LIKE '%GoogleImageProxy%' OR h.remote_host LIKE 'google-proxy-%' OR h.referrer LIKE '%mobile-webview.gmail.com%' OR h.referrer LIKE '%mail.google.com%' THEN 'gmail' WHEN h.user_agent LIKE 'YahooMailProxy%' OR h.remote_host LIKE 'ec%.ycpi.%yahoo.com' THEN 'yahoo_mail' WHEN h.referrer LIKE '%outlook.live.com%' OR h.user_agent LIKE '%OneOutlook/%' OR h.user_agent LIKE '%ms-office%' THEN 'outlook_family' WHEN h.referrer LIKE '%webmail.%' OR h.referrer LIKE '%mail.%' OR h.referrer LIKE '%neo.space%' OR h.referrer LIKE '%titan.email%' THEN 'other_webmail' ELSE 'unknown' END";
	$ispFallbackExpr = "CASE WHEN h.remote_host IS NULL OR TRIM(h.remote_host)='' THEN 'unknown' WHEN h.remote_host REGEXP '^[0-9]+(\\\\.[0-9]+){3}$' THEN 'ip_unresolved' WHEN h.remote_host LIKE 'google-proxy-%' OR h.remote_host LIKE '%.google.com' THEN 'Google' WHEN h.remote_host LIKE '%.yahoo.com' AND h.remote_host LIKE '%.ycpi.%' THEN 'Yahoo' ELSE LOWER(SUBSTRING_INDEX(TRIM(h.remote_host),'.',-2)) END";

	$joinClassification = $classificationAvailable ? " LEFT JOIN $classificationTable c ON c.hit_id = h.id " : '';
	$joinEnrichment = $tableStatus['ip_enrichment'] ? ' LEFT JOIN pd_ip_enrichment e ON e.ip_address = h.ip_address ' : '';
	$clientExpr = $classificationAvailable ? "COALESCE(NULLIF(c.email_client_guess,''), $emailCaseExpr)" : $emailCaseExpr;
	$trafficExpr = $classificationAvailable ? "COALESCE(NULLIF(c.traffic_type,''), 'unknown')" : "CASE WHEN $clientExpr IN ('gmail','yahoo_mail') THEN 'proxy' ELSE 'unknown' END";
	$ispExpr = $classificationAvailable && $tableStatus['ip_enrichment']
		? "COALESCE(NULLIF(c.isp_guess,''), NULLIF(e.isp_name,''), $ispFallbackExpr)"
		: ($classificationAvailable
			? "COALESCE(NULLIF(c.isp_guess,''), $ispFallbackExpr)"
			: ($tableStatus['ip_enrichment'] ? "COALESCE(NULLIF(e.isp_name,''), $ispFallbackExpr)" : $ispFallbackExpr));

	$summarySql =
		"SELECT
			COUNT(*) AS total_hits,
			COUNT(DISTINCT h.ip_address) AS unique_ips,
			COUNT(DISTINCT $referrerDomainExpr) AS unique_referrers,
			SUM(CASE WHEN $trafficExpr = 'proxy' THEN 1 ELSE 0 END) AS proxy_hits,
			SUM(CASE WHEN $trafficExpr = 'human' THEN 1 ELSE 0 END) AS human_hits
		 FROM $hitTable h
		 $joinClassification
		 $joinEnrichment
		 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc";
	$summaryStmt = db()->prepare($summarySql);
	$summaryStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$summary = array_merge($summary, (array) $summaryStmt->fetch());

	$balancedFingerprintExpr = "CONCAT(COALESCE(h.ip_address, ''), '|', MD5(CONCAT(COALESCE(h.user_agent, ''), '|', COALESCE(h.accept_language, ''))))";
	$balancedVisitsSql =
		"WITH ordered_hits AS (
			SELECT
				h.hit_at,
				LAG(h.hit_at) OVER (PARTITION BY $balancedFingerprintExpr ORDER BY h.hit_at) AS prev_hit
			FROM $hitTable h
			WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
		)
		SELECT COALESCE(SUM(CASE WHEN prev_hit IS NULL OR TIMESTAMPDIFF(MINUTE, prev_hit, hit_at) > 30 THEN 1 ELSE 0 END), 0) AS estimated_visits_balanced
		FROM ordered_hits";
	$balancedVisitsStmt = db()->prepare($balancedVisitsSql);
	$balancedVisitsStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$balancedVisitsRow = (array) $balancedVisitsStmt->fetch();
	$summary['estimated_visits_balanced'] = (int) ($balancedVisitsRow['estimated_visits_balanced'] ?? 0);

	$refSql =
		"SELECT $referrerDomainExpr AS ref_domain, COUNT(*) AS hits
		 FROM $hitTable h
		 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
		 GROUP BY ref_domain
		 ORDER BY hits DESC
		 LIMIT 10";
	$refStmt = db()->prepare($refSql);
	$refStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$topReferrers = $refStmt->fetchAll();

	$ispSql =
		"SELECT $ispExpr AS isp, COUNT(*) AS hits, COUNT(DISTINCT h.ip_address) AS unique_ips
		 FROM $hitTable h
		 $joinClassification
		 $joinEnrichment
		 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
		 GROUP BY isp
		 ORDER BY hits DESC
		 LIMIT 10";
	$ispStmt = db()->prepare($ispSql);
	$ispStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$topIsps = $ispStmt->fetchAll();

	if ($tableStatus['ip_enrichment']) {
		$geoSql =
			"SELECT COALESCE(NULLIF(e.country_code, ''), '??') AS country, COUNT(*) AS hits, COUNT(DISTINCT h.ip_address) AS unique_ips
			 FROM $hitTable h
			 LEFT JOIN pd_ip_enrichment e ON e.ip_address = h.ip_address
			 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
			 GROUP BY country
			 ORDER BY hits DESC
			 LIMIT 10";
		$geoStmt = db()->prepare($geoSql);
		$geoStmt->execute([
			'source_id' => (int) $selectedSource['id'],
			'cutoff_utc' => $cutoffUtc,
		]);
		$topCountries = $geoStmt->fetchAll();
	}

	$clientSql =
		"SELECT $clientExpr AS client_name, COUNT(*) AS hits
		 FROM $hitTable h
		 $joinClassification
		 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
		 GROUP BY client_name
		 ORDER BY hits DESC";
	$clientStmt = db()->prepare($clientSql);
	$clientStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$clientMix = $clientStmt->fetchAll();

	$localHitExpr = "IFNULL(CONVERT_TZ(h.hit_at, '+00:00', :tz_name), DATE_ADD(h.hit_at, INTERVAL :tz_offset_minute MINUTE))";

	if ($period === '24h') {
		$timelineSql =
			"SELECT DATE_FORMAT($localHitExpr, '%Y-%m-%d %H:00:00') AS bucket, COUNT(*) AS hits
			 FROM $hitTable h
			 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
			 GROUP BY bucket
			 ORDER BY bucket ASC";
	} else {
		$timelineSql =
			"SELECT DATE($localHitExpr) AS bucket, COUNT(*) AS hits
			 FROM $hitTable h
			 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
			 GROUP BY bucket
			 ORDER BY bucket ASC";
	}
	$timelineStmt = db()->prepare($timelineSql);
	$timelineStmt->bindValue(':tz_name', $appTimezoneName, PDO::PARAM_STR);
	$timelineStmt->bindValue(':tz_offset_minute', $appTimezoneOffsetMinutes, PDO::PARAM_INT);
	$timelineStmt->bindValue(':source_id', (int) $selectedSource['id'], PDO::PARAM_INT);
	$timelineStmt->bindValue(':cutoff_utc', $cutoffUtc, PDO::PARAM_STR);
	$timelineStmt->execute();
	$timelineRows = $timelineStmt->fetchAll();

	if ($heatmapMetric === 'estimated_visits') {
		$heatmapFingerprintExpr = "CONCAT(COALESCE(h.ip_address, ''), '|', MD5(CONCAT(COALESCE(h.user_agent, ''), '|', COALESCE(h.accept_language, ''))))";
		$heatmapSql =
			"WITH ordered_hits AS (
				SELECT
					$localHitExpr AS local_hit_at,
					h.hit_at,
					LAG(h.hit_at) OVER (PARTITION BY $heatmapFingerprintExpr ORDER BY h.hit_at) AS prev_hit
				FROM $hitTable h
				WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
			)
			SELECT DAYOFWEEK(local_hit_at) AS weekday_idx, HOUR(local_hit_at) AS hour_idx,
				COALESCE(SUM(CASE WHEN prev_hit IS NULL OR TIMESTAMPDIFF(MINUTE, prev_hit, hit_at) > 30 THEN 1 ELSE 0 END), 0) AS hits
			FROM ordered_hits
			GROUP BY weekday_idx, hour_idx
			ORDER BY weekday_idx ASC, hour_idx ASC";
	} else {
		$heatmapSql =
			"SELECT DAYOFWEEK($localHitExpr) AS weekday_idx, HOUR($localHitExpr) AS hour_idx, COUNT(*) AS hits
			 FROM $hitTable h
			 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
			 GROUP BY weekday_idx, hour_idx
			 ORDER BY weekday_idx ASC, hour_idx ASC";
	}
	$heatmapStmt = db()->prepare($heatmapSql);
	$heatmapStmt->bindValue(':tz_name', $appTimezoneName, PDO::PARAM_STR);
	$heatmapStmt->bindValue(':tz_offset_minute', $appTimezoneOffsetMinutes, PDO::PARAM_INT);
	$heatmapStmt->bindValue(':source_id', (int) $selectedSource['id'], PDO::PARAM_INT);
	$heatmapStmt->bindValue(':cutoff_utc', $cutoffUtc, PDO::PARAM_STR);
	$heatmapStmt->execute();
	$heatmapRows = $heatmapStmt->fetchAll();

	foreach ($heatmapWeekdayLabels as $weekdayIdx => $weekdayLabel) {
		$heatmapGrid[$weekdayIdx] = [];
		for ($hour = 0; $hour < 24; $hour++) {
			$heatmapGrid[$weekdayIdx][$hour] = 0;
		}
	}

	foreach ($heatmapRows as $heatmapRow) {
		$weekdayIdx = (int) ($heatmapRow['weekday_idx'] ?? 0);
		$hourIdx = (int) ($heatmapRow['hour_idx'] ?? -1);
		$hits = (int) ($heatmapRow['hits'] ?? 0);
		if (!isset($heatmapGrid[$weekdayIdx]) || $hourIdx < 0 || $hourIdx > 23) {
			continue;
		}
		$heatmapGrid[$weekdayIdx][$hourIdx] = $hits;
		if ($hits > $heatmapMaxHits) {
			$heatmapMaxHits = $hits;
		}
	}

	$ipSql =
		"SELECT h.ip_address, COUNT(*) AS hits
		 FROM $hitTable h
		 WHERE h.$idColumn = :source_id AND h.hit_at >= :cutoff_utc
		 GROUP BY h.ip_address
		 ORDER BY hits DESC
		 LIMIT 15";
	$ipStmt = db()->prepare($ipSql);
	$ipStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$topIps = $ipStmt->fetchAll();
}

$displayName = $sourceType === 'redirect' ? 'Redirect Analytics' : 'Pixel Analytics';

render_header('Analytics');
?>
<div class="spaced card">
	<div>
		<h1><?php echo e($displayName); ?></h1>
		<p class="muted">Advanced analytics by source over selected time window.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn" href="stats.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode($sourceKey) : '&pixel_key=' . urlencode($sourceKey); ?>&period=<?php echo urlencode($period); ?>">Open stats</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if (!$hasRedirectTables): ?>
	<div class="error">Redirect analytics tables not migrated yet. Run <a href="../migrate.php">migrations</a> to enable redirect analytics.</div>
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
						<option value="<?php echo e((string) $redirect['redirect_key']); ?>" <?php echo $sourceKey === (string) $redirect['redirect_key'] ? 'selected' : ''; ?>>
							<?php echo e((string) $redirect['redirect_key']); ?> (<?php echo e((string) $redirect['total_hits']); ?>)
						</option>
					<?php endforeach; ?>
				</select>
			<?php else: ?>
				<select name="pixel_key">
					<option value="">Select pixel</option>
					<?php foreach ($pixels as $pixel): ?>
						<option value="<?php echo e((string) $pixel['pixel_key']); ?>" <?php echo $sourceKey === (string) $pixel['pixel_key'] ? 'selected' : ''; ?>>
							<?php echo e((string) $pixel['pixel_key']); ?> (<?php echo e((string) $pixel['total_hits']); ?>)
						</option>
					<?php endforeach; ?>
				</select>
			<?php endif; ?>
		</div>
		<div>
			<label>Period</label>
			<select name="period">
				<?php foreach ($validPeriods as $opt): ?>
					<option value="<?php echo e($opt); ?>" <?php echo $period === $opt ? 'selected' : ''; ?>><?php echo e($opt); ?></option>
				<?php endforeach; ?>
			</select>
		</div>
		<div>
			<label>Heatmap Metric</label>
			<select name="heatmap_metric">
				<option value="hits" <?php echo $heatmapMetric === 'hits' ? 'selected' : ''; ?>>Hits</option>
				<option value="estimated_visits" <?php echo $heatmapMetric === 'estimated_visits' ? 'selected' : ''; ?>>Estimated Visits</option>
			</select>
		</div>
		<div style="align-self:end;"><button type="submit">Load Analytics</button></div>
	</form>
</div>

<?php if (!$tableStatus['ip_enrichment']): ?>
	<div class="error">Analytics enrichment tables are missing. Run <a href="../migrate.php">migrations</a> for full analytics data.</div>
<?php endif; ?>

<?php if ($sourceKey !== '' && !$selectedSource): ?>
	<div class="error"><?php echo e($sourceType === 'redirect' ? 'Redirect not found.' : 'Pixel not found.'); ?></div>
<?php endif; ?>

<?php if ($selectedSource): ?>
	<div class="row">
		<div class="card"><h3>Total Hits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['total_hits'] ?? 0))); ?></p></div>
		<div class="card"><h3>Estimated Visits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['estimated_visits_balanced'] ?? 0))); ?></p></div>
		<div class="card"><h3>Unique IPs</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['unique_ips'] ?? 0))); ?></p></div>
		<!--<div class="card"><h3>Unique Referrers</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['unique_referrers'] ?? 0))); ?></p></div> -->
		<div class="card"><h3>Proxy Hits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['proxy_hits'] ?? 0))); ?></p></div>
	</div>

	<div class="card">
		<h2>Hit Timeline (<?php echo e($period); ?>)</h2>
		<p class="muted">Timezone shown in <?php echo e($appTimezoneName); ?>.</p>
		<?php echo render_simple_svg_chart($timelineRows, 'hits'); ?>
	</div>

	<div class="card">
		<h3>Time-of-Day Heatmap (<?php echo e($appTimezoneName); ?>)</h3>
		<p class="muted"><?php echo e($sourceType === 'redirect' ? 'Click' : 'Open'); ?> concentration by weekday and hour. Metric: <?php echo e($heatmapMetric === 'estimated_visits' ? 'Estimated Visits (Balanced)' : 'Hits'); ?>. Darker cells indicate higher volume.</p>
		<div style="width:100%;overflow-x:auto;">
			<table style="min-width:980px;table-layout:fixed;font-size:0.78rem;">
				<thead>
					<tr>
						<th style="width:56px;padding:4px 6px;">Day</th>
						<?php for ($hour = 0; $hour < 24; $hour++): ?>
							<th style="text-align:center;padding:4px 3px;"><?php echo e(str_pad((string) $hour, 2, '0', STR_PAD_LEFT)); ?></th>
						<?php endfor; ?>
					</tr>
				</thead>
				<tbody>
				<?php foreach ($heatmapWeekdayLabels as $weekdayIdx => $weekdayLabel): ?>
					<tr>
						<td style="padding:4px 6px;"><strong><?php echo e($weekdayLabel); ?></strong></td>
						<?php for ($hour = 0; $hour < 24; $hour++): ?>
							<?php
							$cellHits = (int) ($heatmapGrid[$weekdayIdx][$hour] ?? 0);
							$intensity = $heatmapMaxHits > 0 ? ($cellHits / $heatmapMaxHits) : 0;
							$alpha = $intensity > 0 ? (0.08 + ($intensity * 0.82)) : 0;
							$textColor = $alpha >= 0.58 ? '#ffffff' : '#1f2937';
							$bgColor = $cellHits > 0 ? 'rgba(31, 78, 165, ' . number_format($alpha, 3, '.', '') . ')' : 'transparent';
							?>
							<td style="text-align:center;padding:4px 3px;background:<?php echo e($bgColor); ?>;color:<?php echo e($textColor); ?>;font-weight:<?php echo $cellHits > 0 ? '600' : '400'; ?>;">
								<?php echo e((string) $cellHits); ?>
							</td>
						<?php endfor; ?>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<p class="muted">Peak cell value in window: <?php echo e((string) $heatmapMaxHits); ?></p>
	</div>

	<div class="row">
		<div class="card">
			<h3>Top 10 Referrers</h3>
			<table>
				<thead><tr><th>Referrer Domain</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$topReferrers): ?>
					<tr><td colspan="2" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($topReferrers as $row): ?>
						<tr><td><?php echo e((string) ($row['ref_domain'] ?? '-')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>

		<div class="card">
			<h3>Top 10 ISPs / Providers</h3>
			<table>
				<thead><tr><th>Provider</th><th>Hits</th><th>Unique IPs</th></tr></thead>
				<tbody>
				<?php if (!$topIsps): ?>
					<tr><td colspan="3" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($topIsps as $row): ?>
						<tr><td><?php echo e((string) ($row['isp'] ?? 'unknown')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td><td><?php echo e((string) ($row['unique_ips'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="row">
		<div class="card">
			<h3>Email Client Mix</h3>
			<table>
				<thead><tr><th>Client</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$clientMix): ?>
					<tr><td colspan="2" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($clientMix as $row): ?>
						<tr><td><?php echo e((string) ($row['client_name'] ?? 'unknown')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>

		<div class="card">
			<h3>Top Countries</h3>
			<table>
				<thead><tr><th>Country</th><th>Hits</th><th>Unique IPs</th></tr></thead>
				<tbody>
				<?php if (!$topCountries): ?>
					<tr><td colspan="3" class="muted">No geo data yet.</td></tr>
				<?php else: ?>
					<?php foreach ($topCountries as $row): ?>
						<tr><td><?php echo e((string) ($row['country'] ?? '??')); ?></td><td><?php echo e((string) ($row['hits'] ?? 0)); ?></td><td><?php echo e((string) ($row['unique_ips'] ?? 0)); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="card">
		<h3>Top IPs (click to drill down)</h3>
		<table>
			<thead><tr><th>IP Address</th><th>Hits</th></tr></thead>
			<tbody>
			<?php if (!$topIps): ?>
				<tr><td colspan="2" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($topIps as $row): ?>
					<tr>
						<td><a href="ip-details.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode((string) $selectedSource['source_key']) : '&pixel_key=' . urlencode((string) $selectedSource['source_key']); ?>&ip=<?php echo urlencode((string) ($row['ip_address'] ?? '')); ?>&period=<?php echo urlencode($period); ?>"><?php echo e((string) ($row['ip_address'] ?? '')); ?></a></td>
						<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
<?php endif; ?>
<?php
render_footer();
