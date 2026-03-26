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

$sourceType = trim((string) ($_GET['source_type'] ?? 'pixel'));
if (!in_array($sourceType, ['pixel', 'redirect'], true)) {
	$sourceType = 'pixel';
}

$pixelKey = trim((string) ($_GET['pixel_key'] ?? ''));
$redirectKey = trim((string) ($_GET['redirect_key'] ?? ''));
$sourceKey = $sourceType === 'redirect' ? $redirectKey : $pixelKey;
$period = (string) ($_GET['period'] ?? '7d');
$search = trim((string) ($_GET['search'] ?? ''));
if (function_exists('mb_strlen') && mb_strlen($search) > 255) {
	$search = (string) mb_substr($search, 0, 255);
} elseif (strlen($search) > 255) {
	$search = substr($search, 0, 255);
}
$validPeriods = ['24h', '7d', '30d'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

$chartBucketFormat = $period === '24h' ? 'Y-m-d H:00:00' : 'Y-m-d';
$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');

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
		$stmt = db()->prepare('SELECT id, redirect_key AS source_key, total_hits, created_at, updated_at FROM pd_redirect_links WHERE redirect_key = :source_key LIMIT 1');
		$stmt->execute(['source_key' => $sourceKey]);
		$selectedSource = $stmt->fetch();
	} else {
		$stmt = db()->prepare('SELECT id, pixel_key AS source_key, total_hits, created_at, updated_at FROM pd_pixels WHERE pixel_key = :source_key LIMIT 1');
		$stmt->execute(['source_key' => $sourceKey]);
		$selectedSource = $stmt->fetch();
	}
}

$chartData = [];
$recentHits = [];
$recentHitsPage = max(1, (int) ($_GET['page'] ?? 1));
$recentHitsPerPage = 100;
$recentHitsTotal = 0;
$recentHitsTotalPages = 1;

if ($selectedSource) {
	$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
		->sub(new DateInterval($periodIntervalSpec))
		->format('Y-m-d H:i:s');

	$hitTable = $sourceType === 'redirect' ? 'pd_redirect_hits' : 'pd_pixel_hits';
	$idColumn = $sourceType === 'redirect' ? 'redirect_id' : 'pixel_id';

	$chartStmt = db()->prepare(
		"SELECT hit_at
		 FROM $hitTable
		 WHERE $idColumn = :source_id AND hit_at >= :cutoff_utc
		 ORDER BY hit_at ASC"
	);
	$chartStmt->execute([
		'source_id' => (int) $selectedSource['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$chartRows = $chartStmt->fetchAll();

	$bucketMap = [];
	foreach ($chartRows as $chartRow) {
		$hitUtc = parse_db_datetime_utc((string) ($chartRow['hit_at'] ?? ''));
		if (!$hitUtc) {
			continue;
		}
		$bucket = $hitUtc->setTimezone(app_timezone_object())->format($chartBucketFormat);
		$bucketMap[$bucket] = (int) ($bucketMap[$bucket] ?? 0) + 1;
	}
	ksort($bucketMap);
	foreach ($bucketMap as $bucket => $bucketCount) {
		$chartData[] = [
			'bucket' => $bucket,
			'hit_count' => $bucketCount,
		];
	}

	$totalStmt = db()->prepare("SELECT COUNT(*) AS total FROM $hitTable WHERE $idColumn = :source_id");
	$searchWhereSql = '';
	if ($search !== '') {
		$searchWhereSql = ' AND (hit_at LIKE :search_like OR ip_address LIKE :search_like OR referrer LIKE :search_like OR user_agent LIKE :search_like OR accept_language LIKE :search_like OR remote_host LIKE :search_like)';
	}

	$totalStmt = db()->prepare("SELECT COUNT(*) AS total FROM $hitTable WHERE $idColumn = :source_id$searchWhereSql");
	$totalStmt->bindValue(':source_id', (int) $selectedSource['id'], PDO::PARAM_INT);
	if ($search !== '') {
		$totalStmt->bindValue(':search_like', '%' . $search . '%', PDO::PARAM_STR);
	}
	$totalStmt->execute();
	$recentHitsTotal = (int) ($totalStmt->fetch()['total'] ?? 0);
	$recentHitsTotalPages = max(1, (int) ceil($recentHitsTotal / $recentHitsPerPage));
	if ($recentHitsPage > $recentHitsTotalPages) {
		$recentHitsPage = $recentHitsTotalPages;
	}
	$recentHitsOffset = ($recentHitsPage - 1) * $recentHitsPerPage;

	$recentStmt = db()->prepare(
		"SELECT hit_at, ip_address, user_agent, referrer, accept_language, remote_host
		 FROM $hitTable
		 WHERE $idColumn = :source_id$searchWhereSql
		 ORDER BY hit_at DESC
		 LIMIT :offset, :limit"
	);
	$recentStmt->bindValue(':source_id', (int) $selectedSource['id'], PDO::PARAM_INT);
	if ($search !== '') {
		$recentStmt->bindValue(':search_like', '%' . $search . '%', PDO::PARAM_STR);
	}
	$recentStmt->bindValue(':offset', $recentHitsOffset, PDO::PARAM_INT);
	$recentStmt->bindValue(':limit', $recentHitsPerPage, PDO::PARAM_INT);
	$recentStmt->execute();
	$recentHits = $recentStmt->fetchAll();
}

function render_svg_chart(array $rows): string
{
	if (!$rows) {
		return '<p class="muted">No data in selected period.</p>';
	}

	$width = 900;
	$height = 280;
	$padding = 36;
	$usableWidth = $width - ($padding * 2);
	$usableHeight = $height - ($padding * 2);

	$counts = array_map(static fn($row): int => (int) $row['hit_count'], $rows);
	$maxCount = max($counts);
	if ($maxCount < 1) {
		$maxCount = 1;
	}

	$points = [];
	$labels = [];
	$countRows = count($rows);

	foreach ($rows as $index => $row) {
		$x = $padding + (($countRows <= 1 ? 0 : $index / ($countRows - 1)) * $usableWidth);
		$y = $height - $padding - (((int) $row['hit_count'] / $maxCount) * $usableHeight);
		$points[] = round($x, 2) . ',' . round($y, 2);
		$labels[] = [
			'x' => $x,
			'y' => $height - ($padding - 14),
			'text' => substr((string) $row['bucket'], 5),
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

	$svg .= '<text x="' . ($padding + 4) . '" y="' . ($padding + 10) . '" font-size="10" fill="#666">Max: ' . $maxCount . '</text>';
	$svg .= '</svg>';

	return $svg;
}

$displayName = $sourceType === 'redirect' ? 'Redirect Statistics' : 'Pixel Statistics';
$displayDesc = $sourceType === 'redirect'
	? 'View hit volume and request details per redirect id.'
	: 'View hit volume and request details per pixel id.';

render_header('Stats');
?>
<div class="spaced card">
	<div>
		<h1><?php echo e($displayName); ?></h1>
		<p class="muted"><?php echo e($displayDesc); ?></p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn" href="analytics.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode($sourceKey) : '&pixel_key=' . urlencode($sourceKey); ?>&period=<?php echo urlencode($period); ?>">Analytics</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if (!$hasRedirectTables): ?>
	<div class="error">Redirect analytics tables not migrated yet. Run <a href="../migrate.php">migrations</a> to enable redirect stats.</div>
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
		<div style="align-self:end;"><button type="submit">Load Stats</button></div>
	</form>
</div>

<?php if ($sourceKey !== '' && !$selectedSource): ?>
	<div class="error"><?php echo e($sourceType === 'redirect' ? 'Redirect not found.' : 'Pixel not found.'); ?></div>
<?php endif; ?>

<?php if ($selectedSource): ?>
	<div class="card">
		<h2><?php echo e((string) $selectedSource['source_key']); ?></h2>
		<p class="muted">Total hits: <?php echo e((string) $selectedSource['total_hits']); ?> | Created: <?php echo e(format_db_datetime((string) ($selectedSource['created_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?> (<?php echo e(app_timezone_name()); ?>)</p>
		<?php echo render_svg_chart($chartData); ?>
	</div>

	<div class="card">
		<h3>Recent Hits</h3>
		<p class="muted">Showing <?php echo e((string) ($recentHitsTotal === 0 ? 0 : (($recentHitsPage - 1) * $recentHitsPerPage + 1))); ?>-
			<?php echo e((string) min($recentHitsPage * $recentHitsPerPage, $recentHitsTotal)); ?> of
			<?php echo e((string) $recentHitsTotal); ?></p>
		<div style="margin:10px 0 12px;max-width:520px;">
			<label for="recent-hits-search">Search Recent Hits</label>
			<form method="get" id="recent-hits-search-form">
				<input type="hidden" name="source_type" value="<?php echo e($sourceType); ?>">
				<?php if ($sourceType === 'redirect'): ?>
					<input type="hidden" name="redirect_key" value="<?php echo e((string) $selectedSource['source_key']); ?>">
				<?php else: ?>
					<input type="hidden" name="pixel_key" value="<?php echo e((string) $selectedSource['source_key']); ?>">
				<?php endif; ?>
				<input type="hidden" name="period" value="<?php echo e($period); ?>">
				<div class="inline" style="gap:8px;align-items:center;flex-wrap:nowrap;">
					<input type="text" name="search" id="recent-hits-search" value="<?php echo e($search); ?>" placeholder="Search Date/Time, IP, Referrer, User Agent, Language, or Host" style="flex:1 1 auto;min-width:0;">
					<?php if ($search !== ''): ?>
						<button type="button" style="white-space:nowrap;" onclick="window.location.href='stats.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode((string) $selectedSource['source_key']) : '&pixel_key=' . urlencode((string) $selectedSource['source_key']); ?>&period=<?php echo urlencode($period); ?>';">Clear Search</button>
					<?php endif; ?>
				</div>
			</form>
		</div>
		<div style="width:100%;overflow-x:auto;">
		<table style="min-width:100%;table-layout:fixed;">
			<thead>
			<tr>
				<th>Date/Time</th>
				<th>IP</th>
				<th>Referrer</th>
				<th>User Agent</th>
				<th>Language</th>
				<th>Host</th>
			</tr>
			</thead>
			<tbody>
			<?php if (!$recentHits): ?>
				<tr><td colspan="6" class="muted">No hits yet.</td></tr>
			<?php else: ?>
				<?php foreach ($recentHits as $hit): ?>
					<?php $hitIp = (string) ($hit['ip_address'] ?? ''); ?>
					<tr>
						<td style="word-break:break-word;"><?php echo e(format_db_datetime((string) ($hit['hit_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td>
							<?php if ($hitIp !== ''): ?>
								<a href="ip-details.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode((string) $selectedSource['source_key']) : '&pixel_key=' . urlencode((string) $selectedSource['source_key']); ?>&ip=<?php echo urlencode($hitIp); ?>&period=<?php echo urlencode($period); ?>"><?php echo e($hitIp); ?></a>
							<?php else: ?>
								-
							<?php endif; ?>
						</td>
						<td style="word-break:break-word;"><?php echo e((string) ($hit['referrer'] ?: '-')); ?></td>
						<td style="word-break:break-word;"><?php echo e((string) ($hit['user_agent'] ?: '-')); ?></td>
						<td style="word-break:break-word;"><?php echo e((string) ($hit['accept_language'] ?: '-')); ?></td>
						<td style="word-break:break-word;"><?php echo e((string) ($hit['remote_host'] ?: '-')); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
		</div>
		<?php if ($recentHitsTotalPages > 1): ?>
			<div class="inline" style="margin-top:12px;">
				<?php if ($recentHitsPage > 1): ?>
					<a href="stats.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode((string) $selectedSource['source_key']) : '&pixel_key=' . urlencode((string) $selectedSource['source_key']); ?>&period=<?php echo urlencode($period); ?><?php echo $search !== '' ? '&search=' . urlencode($search) : ''; ?>&page=<?php echo (int) ($recentHitsPage - 1); ?>">&laquo; Prev</a>
				<?php endif; ?>
				<span class="muted">Page <?php echo e((string) $recentHitsPage); ?> of <?php echo e((string) $recentHitsTotalPages); ?></span>
				<?php if ($recentHitsPage < $recentHitsTotalPages): ?>
					<a href="stats.php?source_type=<?php echo urlencode($sourceType); ?><?php echo $sourceType === 'redirect' ? '&redirect_key=' . urlencode((string) $selectedSource['source_key']) : '&pixel_key=' . urlencode((string) $selectedSource['source_key']); ?>&period=<?php echo urlencode($period); ?><?php echo $search !== '' ? '&search=' . urlencode($search) : ''; ?>&page=<?php echo (int) ($recentHitsPage + 1); ?>">Next &raquo;</a>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</div>
<?php endif; ?>
<script>
var recentHitsSearchInput = document.getElementById('recent-hits-search');
var recentHitsSearchForm = document.getElementById('recent-hits-search-form');
if (recentHitsSearchInput && recentHitsSearchForm) {
	var recentHitsSearchTimer = null;
	var recentHitsShouldRefocus = false;
	try {
		recentHitsShouldRefocus = window.sessionStorage.getItem('recentHitsRefocus') === '1';
		if (recentHitsShouldRefocus) {
			window.sessionStorage.removeItem('recentHitsRefocus');
		}
	} catch (e) {
		recentHitsShouldRefocus = false;
	}

	if (recentHitsShouldRefocus || (recentHitsSearchInput.value || '').trim() !== '') {
		setTimeout(function () {
			recentHitsSearchInput.focus();
			var valueLength = recentHitsSearchInput.value.length;
			if (recentHitsSearchInput.setSelectionRange) {
				recentHitsSearchInput.setSelectionRange(valueLength, valueLength);
			}
		}, 0);
	}

	var submitSearch = function () {
		try {
			window.sessionStorage.setItem('recentHitsRefocus', '1');
		} catch (e) {
		}
		recentHitsSearchForm.submit();
	};

	recentHitsSearchInput.addEventListener('input', function () {
		clearTimeout(recentHitsSearchTimer);
		recentHitsSearchTimer = setTimeout(submitSearch, 900);
	});

	recentHitsSearchInput.addEventListener('paste', function () {
		clearTimeout(recentHitsSearchTimer);
		recentHitsSearchTimer = setTimeout(submitSearch, 0);
	});
}
</script>
<?php
render_footer();
