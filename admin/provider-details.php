<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

require_admin();

$provider = trim((string) ($_GET['provider'] ?? ''));
$period = (string) ($_GET['period'] ?? '7d');
$page = max(1, (int) ($_GET['page'] ?? 1));
$ipPerPage = 25;
$recentPage = max(1, (int) ($_GET['recent_page'] ?? 1));
$recentPerPage = 25;
$displayTimezoneName = app_timezone_name();
$displayTimezone = app_timezone_object();
$formatUtcToLocal = static function (?string $value) use ($displayTimezone): string {
	$raw = trim((string) $value);
	if ($raw === '') {
		return '-';
	}

	$dateTimeUtc = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $raw, new DateTimeZone('UTC'));
	if ($dateTimeUtc instanceof DateTimeImmutable) {
		return $dateTimeUtc->setTimezone($displayTimezone)->format('Y-m-d H:i:s');
	}

	try {
		return (new DateTimeImmutable($raw, new DateTimeZone('UTC')))->setTimezone($displayTimezone)->format('Y-m-d H:i:s');
	} catch (Throwable $e) {
		return '-';
	}
};

$validPeriods = ['24h', '7d', '30d', 'all'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

if ($period === 'all') {
	$cutoffUtc = '1970-01-01 00:00:00';
} else {
	$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');
	$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
		->sub(new DateInterval($periodIntervalSpec))
		->format('Y-m-d H:i:s');
}

$tableStatus = analytics_table_status();
$pdo = db();
$hasPixelHits = table_exists($pdo, 'pd_pixel_hits');
$hasRedirectHits = table_exists($pdo, 'pd_redirect_hits');
$hasAdHits = table_exists($pdo, 'pd_ad_hit_logs');
$hasIpEnrichment = (bool) ($tableStatus['ip_enrichment'] ?? false);
$hasPixelClassification = (bool) ($tableStatus['hit_classification'] ?? false);
$hasRedirectClassification = (bool) ($tableStatus['redirect_hit_classification'] ?? false);

$summary = [
	'total_hits' => 0,
	'unique_ips' => 0,
	'first_seen' => null,
	'last_seen' => null,
];
$sourceRows = [];
$sourceKeyRows = [];
$ipRows = [];
$recentRows = [];
$totalIps = 0;
$totalPages = 1;
$recentTotalRows = 0;
$recentTotalPages = 1;
$recentDisplayStart = 0;
$recentDisplayEnd = 0;
$displayStart = 0;
$displayEnd = 0;
$ipTagMap = [];
$errorMessage = '';

$ispFallbackExpr = "CASE WHEN h.remote_host IS NULL OR TRIM(h.remote_host)='' THEN 'unknown' WHEN h.remote_host REGEXP '^[0-9]+(\\\\.[0-9]+){3}$' THEN 'unknown' WHEN h.remote_host LIKE 'google-proxy-%' OR h.remote_host LIKE '%.google.com' THEN 'Google' WHEN h.remote_host LIKE '%.yahoo.com' AND h.remote_host LIKE '%.ycpi.%' THEN 'Yahoo' ELSE LOWER(SUBSTRING_INDEX(TRIM(h.remote_host),'.',-2)) END";

$parts = [];
$params = [];

if ($hasPixelHits) {
	$pixelProviderExpr = $hasPixelClassification && $hasIpEnrichment
		? "COALESCE(NULLIF(c.isp_guess,''), NULLIF(e.isp_name,''), $ispFallbackExpr)"
		: ($hasPixelClassification
			? "COALESCE(NULLIF(c.isp_guess,''), $ispFallbackExpr)"
			: ($hasIpEnrichment ? "COALESCE(NULLIF(e.isp_name,''), $ispFallbackExpr)" : $ispFallbackExpr));

	$parts[] =
		"SELECT
			'pixel' AS source_type,
			h.pixel_key AS source_key,
			h.hit_at,
			h.ip_address,
			$pixelProviderExpr AS provider_name
		 FROM pd_pixel_hits h"
		. ($hasPixelClassification ? ' LEFT JOIN pd_hit_classification c ON c.hit_id = h.id' : '')
		. ($hasIpEnrichment ? ' LEFT JOIN pd_ip_enrichment e ON e.ip_address = h.ip_address' : '')
		. ' WHERE h.hit_at >= ?';
	$params[] = $cutoffUtc;
}

if ($hasRedirectHits) {
	$redirectProviderExpr = $hasRedirectClassification && $hasIpEnrichment
		? "COALESCE(NULLIF(c.isp_guess,''), NULLIF(e.isp_name,''), $ispFallbackExpr)"
		: ($hasRedirectClassification
			? "COALESCE(NULLIF(c.isp_guess,''), $ispFallbackExpr)"
			: ($hasIpEnrichment ? "COALESCE(NULLIF(e.isp_name,''), $ispFallbackExpr)" : $ispFallbackExpr));

	$parts[] =
		"SELECT
			'redirect' AS source_type,
			h.redirect_key AS source_key,
			h.hit_at,
			h.ip_address,
			$redirectProviderExpr AS provider_name
		 FROM pd_redirect_hits h"
		. ($hasRedirectClassification ? ' LEFT JOIN pd_redirect_hit_classification c ON c.hit_id = h.id' : '')
		. ($hasIpEnrichment ? ' LEFT JOIN pd_ip_enrichment e ON e.ip_address = h.ip_address' : '')
		. ' WHERE h.hit_at >= ?';
	$params[] = $cutoffUtc;
}

if ($hasAdHits) {
	$parts[] =
		"SELECT
			'ad' AS source_type,
			h.ad_key AS source_key,
			h.hit_at,
			h.ip_address,
			COALESCE(NULLIF(TRIM(h.isp_name), ''), 'unknown') AS provider_name
		 FROM pd_ad_hit_logs h
		 WHERE h.hit_at >= ?";
	$params[] = $cutoffUtc;
}

if (!$parts) {
	$errorMessage = 'No analytics hit tables are available yet.';
}

if ($provider === '') {
	$errorMessage = $errorMessage === '' ? 'Select a provider from analytics to view details.' : $errorMessage;
}

if ($errorMessage === '') {
	$unionSql = implode(' UNION ALL ', $parts);
	$providerParams = array_merge($params, [$provider]);

	try {
		$summaryStmt = $pdo->prepare(
			"SELECT
				COUNT(*) AS total_hits,
				COUNT(DISTINCT u.ip_address) AS unique_ips,
				MIN(u.hit_at) AS first_seen,
				MAX(u.hit_at) AS last_seen
			 FROM ($unionSql) u
			 WHERE u.provider_name = ?"
		);
		$summaryStmt->execute($providerParams);
		$summary = array_merge($summary, (array) $summaryStmt->fetch());

		$sourceStmt = $pdo->prepare(
			"SELECT u.source_type, COUNT(*) AS hits, COUNT(DISTINCT u.ip_address) AS unique_ips
			 FROM ($unionSql) u
			 WHERE u.provider_name = ?
			 GROUP BY u.source_type
			 ORDER BY hits DESC, u.source_type ASC"
		);
		$sourceStmt->execute($providerParams);
		$sourceRows = $sourceStmt->fetchAll();

		$sourceKeyStmt = $pdo->prepare(
			"SELECT u.source_type, u.source_key, COUNT(*) AS hits
			 FROM ($unionSql) u
			 WHERE u.provider_name = ?
			 GROUP BY u.source_type, u.source_key
			 ORDER BY hits DESC, u.source_type ASC, u.source_key ASC
			 LIMIT 30"
		);
		$sourceKeyStmt->execute($providerParams);
		$sourceKeyRows = $sourceKeyStmt->fetchAll();

		$totalIpsStmt = $pdo->prepare(
			"SELECT COUNT(*) AS total_ips FROM (
				SELECT u.ip_address
				FROM ($unionSql) u
				WHERE u.provider_name = ?
				GROUP BY u.ip_address
			) ip_rows"
		);
		$totalIpsStmt->execute($providerParams);
		$totalIps = (int) (($totalIpsStmt->fetch()['total_ips'] ?? 0));
		$totalPages = max(1, (int) ceil($totalIps / $ipPerPage));
		if ($page > $totalPages) {
			$page = $totalPages;
		}
		$offset = ($page - 1) * $ipPerPage;

		$ipSql =
			"SELECT u.ip_address, COUNT(*) AS hits, MAX(u.hit_at) AS last_seen, COUNT(DISTINCT u.source_type) AS source_count
			 FROM ($unionSql) u
			 WHERE u.provider_name = ?
			 GROUP BY u.ip_address
			 ORDER BY hits DESC, last_seen DESC
			 LIMIT ? OFFSET ?";
		$ipStmt = $pdo->prepare($ipSql);
		$bindPos = 1;
		foreach ($providerParams as $value) {
			$ipStmt->bindValue($bindPos++, $value, PDO::PARAM_STR);
		}
		$ipStmt->bindValue($bindPos++, $ipPerPage, PDO::PARAM_INT);
		$ipStmt->bindValue($bindPos, $offset, PDO::PARAM_INT);
		$ipStmt->execute();
		$ipRows = $ipStmt->fetchAll();

		$recentTotalStmt = $pdo->prepare(
			"SELECT COUNT(*) AS total
			 FROM ($unionSql) u
			 WHERE u.provider_name = ?"
		);
		$recentTotalStmt->execute($providerParams);
		$recentTotalRows = (int) (($recentTotalStmt->fetch()['total'] ?? 0));
		$recentTotalPages = max(1, (int) ceil($recentTotalRows / $recentPerPage));
		if ($recentPage > $recentTotalPages) {
			$recentPage = $recentTotalPages;
		}
		$recentOffset = ($recentPage - 1) * $recentPerPage;

		$recentSql =
			"SELECT u.source_type, u.source_key, u.hit_at, u.ip_address
			 FROM ($unionSql) u
			 WHERE u.provider_name = ?
			 ORDER BY u.hit_at DESC
			 LIMIT ? OFFSET ?";
		$recentStmt = $pdo->prepare($recentSql);
		$recentBindPos = 1;
		foreach ($providerParams as $value) {
			$recentStmt->bindValue($recentBindPos++, $value, PDO::PARAM_STR);
		}
		$recentStmt->bindValue($recentBindPos++, $recentPerPage, PDO::PARAM_INT);
		$recentStmt->bindValue($recentBindPos, $recentOffset, PDO::PARAM_INT);
		$recentStmt->execute();
		$recentRows = $recentStmt->fetchAll();

		$ipLookup = [];
		foreach ($ipRows as $row) {
			$ipLookup[] = (string) ($row['ip_address'] ?? '');
		}
		foreach ($recentRows as $row) {
			$ipLookup[] = (string) ($row['ip_address'] ?? '');
		}
		$ipTagMap = fetch_ip_operator_tags($ipLookup);
	} catch (Throwable $e) {
		$errorMessage = 'Unable to load provider details right now.';
	}
}

if ($totalIps > 0) {
	$displayStart = (($page - 1) * $ipPerPage) + 1;
	$displayEnd = min((($page - 1) * $ipPerPage) + count($ipRows), $totalIps);
}
if ($recentTotalRows > 0) {
	$recentDisplayStart = (($recentPage - 1) * $recentPerPage) + 1;
	$recentDisplayEnd = min((($recentPage - 1) * $recentPerPage) + count($recentRows), $recentTotalRows);
}

render_header('Provider Details');
?>
<div class="spaced card">
	<div>
		<h1>Provider Details</h1>
		<p class="muted">Unified provider drilldown across pixel, redirect, and targeted ad events.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn" href="analytics.php">Pixel/Redirect analytics</a>
		<a class="nav-btn" href="ad-analytics.php">Targeted ad analytics</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<div class="card">
	<form method="get" class="row">
		<div>
			<label>Provider</label>
			<input type="text" name="provider" value="<?php echo e($provider); ?>" placeholder="Provider name">
		</div>
		<div>
			<label>Period</label>
			<select name="period">
				<option value="24h" <?php echo $period === '24h' ? 'selected' : ''; ?>>Last 24 hours</option>
				<option value="7d" <?php echo $period === '7d' ? 'selected' : ''; ?>>Last 7 days</option>
				<option value="30d" <?php echo $period === '30d' ? 'selected' : ''; ?>>Last 30 days</option>
				<option value="all" <?php echo $period === 'all' ? 'selected' : ''; ?>>All time</option>
			</select>
		</div>
		<div style="align-self:end;">
			<button type="submit">Apply</button>
		</div>
	</form>
</div>

<?php if ($errorMessage !== ''): ?>
	<div class="error"><?php echo e($errorMessage); ?></div>
	<?php render_footer(); return; ?>
<?php endif; ?>

<div class="card">
	<h2><?php echo e($provider); ?></h2>
	<div class="summary-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;">
		<div class="summary-bubble" style="border:1px solid #dbe4f5;background:#f6f9ff;border-radius:999px;padding:12px 14px;line-height:1.2;">
			<strong style="display:block;font-size:1.15rem;color:#1f4ea5;"><?php echo number_format((int) ($summary['total_hits'] ?? 0)); ?></strong>
			<span class="muted">Total hits</span>
		</div>
		<div class="summary-bubble" style="border:1px solid #dbe4f5;background:#f6f9ff;border-radius:999px;padding:12px 14px;line-height:1.2;">
			<strong style="display:block;font-size:1.15rem;color:#1f4ea5;"><?php echo number_format((int) ($summary['unique_ips'] ?? 0)); ?></strong>
			<span class="muted">Unique IPs</span>
		</div>
		<div class="summary-bubble" style="border:1px solid #dbe4f5;background:#f6f9ff;border-radius:999px;padding:12px 14px;line-height:1.2;">
			<strong style="display:block;font-size:1.15rem;color:#1f4ea5;"><?php echo e($formatUtcToLocal((string) ($summary['first_seen'] ?? ''))); ?></strong>
			<span class="muted">First seen (<?php echo e($displayTimezoneName); ?>)</span>
		</div>
		<div class="summary-bubble" style="border:1px solid #dbe4f5;background:#f6f9ff;border-radius:999px;padding:12px 14px;line-height:1.2;">
			<strong style="display:block;font-size:1.15rem;color:#1f4ea5;"><?php echo e($formatUtcToLocal((string) ($summary['last_seen'] ?? ''))); ?></strong>
			<span class="muted">Last seen (<?php echo e($displayTimezoneName); ?>)</span>
		</div>
	</div>
</div>

<div class="row" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;">
	<div class="card">
		<h3>Source Breakdown</h3>
		<table>
			<thead><tr><th>Source</th><th>Hits</th><th>Unique IPs</th></tr></thead>
			<tbody>
			<?php if (!$sourceRows): ?>
				<tr><td colspan="3" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($sourceRows as $row): ?>
					<tr>
						<td><?php echo e((string) ucfirst((string) ($row['source_type'] ?? ''))); ?></td>
						<td><?php echo number_format((int) ($row['hits'] ?? 0)); ?></td>
						<td><?php echo number_format((int) ($row['unique_ips'] ?? 0)); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
	<div class="card">
		<h3>Top Source Keys</h3>
		<table>
			<thead><tr><th>Source</th><th>Key</th><th>Hits</th></tr></thead>
			<tbody>
			<?php if (!$sourceKeyRows): ?>
				<tr><td colspan="3" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($sourceKeyRows as $row): ?>
					<?php
					$stype = (string) ($row['source_type'] ?? '');
					$skey = (string) ($row['source_key'] ?? '');
					$link = '#';
					if ($stype === 'redirect') {
						$link = 'analytics.php?' . http_build_query(['source_type' => 'redirect', 'redirect_key' => $skey, 'period' => $period]);
					} elseif ($stype === 'pixel') {
						$link = 'analytics.php?' . http_build_query(['source_type' => 'pixel', 'pixel_key' => $skey, 'period' => $period]);
					} elseif ($stype === 'ad') {
						$link = 'ad-analytics.php?' . http_build_query(['ad_key' => $skey, 'period' => $period, 'provider' => $provider]);
					}
					?>
					<tr>
						<td><?php echo e(ucfirst($stype)); ?></td>
						<td><a href="<?php echo e($link); ?>"><?php echo e($skey); ?></a></td>
						<td><?php echo number_format((int) ($row['hits'] ?? 0)); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>

<div class="card">
	<h3>IP Addresses for Provider</h3>
	<p class="muted">Showing <?php echo number_format($displayStart); ?>-<?php echo number_format($displayEnd); ?> of <?php echo number_format($totalIps); ?> IPs.</p>
	<table>
		<thead><tr><th>IP Address</th><th>Hits</th><th>Sources</th><th>Last Seen (<?php echo e($displayTimezoneName); ?>)</th></tr></thead>
		<tbody>
		<?php if (!$ipRows): ?>
			<tr><td colspan="4" class="muted">No IPs matched this provider in selected period.</td></tr>
		<?php else: ?>
			<?php foreach ($ipRows as $row): ?>
				<?php
				$ipValue = (string) ($row['ip_address'] ?? '');
				$ipLabel = format_ip_with_operator_tag($ipValue, (string) ($ipTagMap[$ipValue] ?? ''));
				$ipHref = 'ip-details.php?' . http_build_query(['source_type' => 'all', 'period' => $period, 'ip' => $ipValue]);
				?>
				<tr>
					<td><a href="<?php echo e($ipHref); ?>"><?php echo e($ipLabel !== '' ? $ipLabel : $ipValue); ?></a></td>
					<td><?php echo number_format((int) ($row['hits'] ?? 0)); ?></td>
					<td><?php echo number_format((int) ($row['source_count'] ?? 0)); ?></td>
					<td><?php echo e($formatUtcToLocal((string) ($row['last_seen'] ?? ''))); ?></td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
		</tbody>
	</table>

	<?php if ($totalPages > 1): ?>
		<?php $baseParams = ['provider' => $provider, 'period' => $period, 'recent_page' => $recentPage]; ?>
		<div class="inline" style="margin-top:10px;gap:10px;">
			<?php if ($page > 1): ?>
				<?php $firstParams = $baseParams; $firstParams['page'] = 1; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($firstParams)); ?>">First</a>
				<?php $prevParams = $baseParams; $prevParams['page'] = $page - 1; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($prevParams)); ?>">Previous</a>
			<?php endif; ?>
			<span class="muted">Page <?php echo (int) $page; ?> of <?php echo (int) $totalPages; ?></span>
			<?php if ($page < $totalPages): ?>
				<?php $nextParams = $baseParams; $nextParams['page'] = $page + 1; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($nextParams)); ?>">Next</a>
				<?php $lastParams = $baseParams; $lastParams['page'] = $totalPages; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($lastParams)); ?>">Last</a>
			<?php endif; ?>
		</div>
	<?php endif; ?>
</div>

<div class="card">
	<h3>Recent Provider Hits</h3>
	<p class="muted">Showing <?php echo number_format($recentDisplayStart); ?>-<?php echo number_format($recentDisplayEnd); ?> of <?php echo number_format($recentTotalRows); ?> hits.</p>
	<table>
		<thead><tr><th>Time (<?php echo e($displayTimezoneName); ?>)</th><th>Source</th><th>Source Key</th><th>IP</th></tr></thead>
		<tbody>
		<?php if (!$recentRows): ?>
			<tr><td colspan="4" class="muted">No recent hits.</td></tr>
		<?php else: ?>
			<?php foreach ($recentRows as $row): ?>
				<?php
				$recentIp = (string) ($row['ip_address'] ?? '');
				$recentIpLabel = format_ip_with_operator_tag($recentIp, (string) ($ipTagMap[$recentIp] ?? ''));
				$recentIpHref = 'ip-details.php?' . http_build_query(['source_type' => 'all', 'period' => $period, 'ip' => $recentIp]);
				?>
				<tr>
					<td><?php echo e($formatUtcToLocal((string) ($row['hit_at'] ?? ''))); ?></td>
					<td><?php echo e(ucfirst((string) ($row['source_type'] ?? ''))); ?></td>
					<td><?php echo e((string) ($row['source_key'] ?? '')); ?></td>
					<td><a href="<?php echo e($recentIpHref); ?>"><?php echo e($recentIpLabel !== '' ? $recentIpLabel : $recentIp); ?></a></td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
		</tbody>
	</table>

	<?php if ($recentTotalPages > 1): ?>
		<?php $recentBaseParams = ['provider' => $provider, 'period' => $period, 'page' => $page]; ?>
		<div class="inline" style="margin-top:10px;gap:10px;">
			<?php if ($recentPage > 1): ?>
				<?php $recentFirstParams = $recentBaseParams; $recentFirstParams['recent_page'] = 1; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($recentFirstParams)); ?>">First</a>
				<?php $recentPrevParams = $recentBaseParams; $recentPrevParams['recent_page'] = $recentPage - 1; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($recentPrevParams)); ?>">Previous</a>
			<?php endif; ?>
			<span class="muted">Page <?php echo (int) $recentPage; ?> of <?php echo (int) $recentTotalPages; ?></span>
			<?php if ($recentPage < $recentTotalPages): ?>
				<?php $recentNextParams = $recentBaseParams; $recentNextParams['recent_page'] = $recentPage + 1; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($recentNextParams)); ?>">Next</a>
				<?php $recentLastParams = $recentBaseParams; $recentLastParams['recent_page'] = $recentTotalPages; ?>
				<a class="nav-btn" href="provider-details.php?<?php echo e(http_build_query($recentLastParams)); ?>">Last</a>
			<?php endif; ?>
		</div>
	<?php endif; ?>
</div>

<?php render_footer();
