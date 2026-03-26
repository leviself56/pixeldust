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

$admin = current_admin();
$error = null;
$successMsg = flash('success');
$createdPixelKey = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$rawPixelKey = trim((string) ($_POST['pixel_key'] ?? ''));
	$pixelKey = sanitize_pixel_key($rawPixelKey);

	if ($pixelKey === '') {
		$error = 'Pixel id is required and must contain letters and/or numbers.';
	} else {
		try {
			$existingStmt = db()->prepare('SELECT id, created_at FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
			$existingStmt->execute(['pixel_key' => $pixelKey]);
			$existingPixel = $existingStmt->fetch();

			create_pixel_if_missing($pixelKey, (int) $admin['id']);
			$_SESSION['created_pixel_key'] = $pixelKey;

			if ($existingPixel) {
				$successMsg = 'Pixel already existed: ' . $pixelKey . ' (it may have been auto-created by a prior /pix.php?id= request).';
			} else {
				$successMsg = 'Pixel created: ' . $pixelKey;
			}

			$createdPixelKey = $pixelKey;
		} catch (Throwable $e) {
			$error = 'Could not create pixel: ' . $e->getMessage();
		}
	}
}

$pixels = [];
try {
	$pixels = db()->query(
		'SELECT id, pixel_key, label, total_hits, created_at, updated_at
		 FROM pd_pixels
		 ORDER BY updated_at DESC, id DESC'
	)->fetchAll();

	$lastHitMap = [];
	$lastHitRows = db()->query(
		'SELECT pixel_id, MAX(hit_at) AS last_hit_at
		 FROM pd_pixel_hits
		 GROUP BY pixel_id'
	)->fetchAll();

	foreach ($lastHitRows as $lastHitRow) {
		$lastHitMap[(int) $lastHitRow['pixel_id']] = (string) ($lastHitRow['last_hit_at'] ?? '');
	}

	foreach ($pixels as &$pixel) {
		$pixelId = (int) $pixel['id'];
		$pixel['last_hit_at'] = $lastHitMap[$pixelId] ?? '';
	}
	unset($pixel);
} catch (Throwable $e) {
	$error = 'Could not load pixel table: ' . $e->getMessage();
}

$totalPixels = count($pixels);
$totalHits = (int) (db()->query('SELECT COALESCE(SUM(total_hits), 0) AS total FROM pd_pixels')->fetch()['total'] ?? 0);

$defaultTriggerId = null;
try {
	$defaultTriggerStmt = db()->query('SELECT trigger_id FROM pd_trigger_actions WHERE is_default = 1 AND is_active = 1 ORDER BY updated_at DESC, id DESC LIMIT 1');
	$defaultTrigger = $defaultTriggerStmt->fetch();
	if ($defaultTrigger && isset($defaultTrigger['trigger_id'])) {
		$defaultTriggerId = (string) $defaultTrigger['trigger_id'];
	}
} catch (Throwable $e) {
}

render_header('Admin Dashboard');
?>
<div class="spaced card">
	<div>
		<h1>Pixel Dust Admin</h1>
		<p class="muted">Logged in as <?php echo e((string) $admin['username']); ?></p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="stats.php">View detailed stats</a>
		<a class="nav-btn" href="analytics.php">View analytics</a>
		<a class="nav-btn" href="users.php">Manage users</a>
		<a class="nav-btn" href="triggers.php">Manage triggers</a>
		<a class="nav-btn" href="../migrate.php">Run migrations</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if ($successMsg): ?>
	<div class="success"><?php echo e($successMsg); ?></div>
<?php endif; ?>
<?php if ($error): ?>
	<div class="error"><?php echo e($error); ?></div>
<?php endif; ?>

<?php if ($createdPixelKey !== null): ?>
	<?php
	$createdPixelUrl = base_url() . '/pix.php?id=' . urlencode($createdPixelKey);
	if ($defaultTriggerId !== null && $defaultTriggerId !== '') {
		$createdPixelUrl .= '&trigger=' . urlencode($defaultTriggerId);
	}
	?>
	<?php $createdPixelTag = '<img src="' . $createdPixelUrl . '" width="1" height="1" style="display:none;" alt="" />'; ?>
	<div class="card">
		<h2>Embed Code</h2>
		<p class="muted">Use this pixel URL/snippet in blog posts, emails, or websites.</p>
		<?php if ($defaultTriggerId !== null && $defaultTriggerId !== ''): ?>
			<p class="muted">Default trigger applied: <?php echo e($defaultTriggerId); ?></p>
		<?php endif; ?>
		<p>
			<label>Direct Pixel URL</label>
			<span class="inline" style="display:flex;align-items:center;gap:8px;">
				<input id="created-pixel-url" value="<?php echo e($createdPixelUrl); ?>" readonly onclick="this.select()" style="flex:1;min-width:260px;width:auto;">
				<button type="button" onclick="copyToClipboard('created-pixel-url', this)">Copy Link</button>
			</span>
		</p>
		<p><label>HTML Embed Snippet</label><input value="<?php echo e($createdPixelTag); ?>" readonly onclick="this.select()"></p>
	</div>
<?php endif; ?>

<div class="row">
	<div class="card">
		<h3>Total Pixels</h3>
		<p style="font-size:1.6rem;font-weight:bold;"><?php echo e((string) $totalPixels); ?></p>
	</div>
	<div class="card">
		<h3>Total Hits</h3>
		<p style="font-size:1.6rem;font-weight:bold;"><?php echo e((string) $totalHits); ?></p>
	</div>
</div>

<div class="card">
	<h2>Create Pixel</h2>
	<form method="post" class="inline">
		<div style="flex:1;min-width:240px;">
			<label>Pixel ID (example: blog_post_title)</label>
			<input type="text" id="pixel_key" name="pixel_key" required maxlength="191" placeholder="blog_post_title" oninput="sanitizePixelKeyInput(this)">
			<p class="muted">Spaces become underscores. Only letters, numbers, and underscores are kept.</p>
		</div>
		<div style="padding-top:22px;">
			<button type="submit">Create</button>
		</div>
	</form>
</div>

<div class="card">
	<h2>Pixels</h2>	
	<p>
		<label for="pixel-search">Search Pixel IDs</label>
		<input type="text" id="pixel-search" placeholder="Type or paste a pixel id to filter" oninput="filterPixelRows(this.value)">
	</p>
	<?php if ($pixels): ?>
		<?php
		$quickIds = [];
		foreach ($pixels as $quickPixel) {
			$quickIds[] = (string) $quickPixel['pixel_key'];
		}
		?>		
	<?php endif; ?>
	<div style="width:100%;overflow-x:auto;">
	<table style="min-width:100%;table-layout:fixed;">
		<thead>
			<tr>
				<th>ID</th>
				<th>Hits</th>
				<th>Last Hit</th>
				<th>Embed</th>
				<th>Stats</th>
				<th>Analytics</th>
			</tr>
		</thead>
		<tbody>
			<?php if (!$pixels): ?>
				<tr id="pixel-empty-row"><td colspan="6" class="muted">No pixels yet.</td></tr>
			<?php else: ?>
				<?php foreach ($pixels as $pixel): ?>
						<?php
						$embed = base_url() . '/pix.php?id=' . urlencode((string) $pixel['pixel_key']);
						if ($defaultTriggerId !== null && $defaultTriggerId !== '') {
							$embed .= '&trigger=' . urlencode($defaultTriggerId);
						}
						?>
					<tr class="pixel-row" data-pixel-key="<?php echo e((string) $pixel['pixel_key']); ?>">
						<td style="word-break:break-word;"><?php echo e((string) $pixel['pixel_key']); ?></td>
						<td style="word-break:break-word;"><?php echo e((string) $pixel['total_hits']); ?></td>
						<td style="word-break:break-word;"><?php echo e(format_db_datetime((string) ($pixel['last_hit_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td>
							<button type="button" onclick='copyTextValue(<?php echo json_encode($embed, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>, this)'>Copy Embed Link</button>
						</td>
						<td><a class="nav-btn" href="stats.php?pixel_key=<?php echo urlencode((string) $pixel['pixel_key']); ?>">Open</a></td>
						<td><a class="nav-btn" href="analytics.php?pixel_key=<?php echo urlencode((string) $pixel['pixel_key']); ?>">Open</a></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
		</tbody>
	</table>
	</div>
</div>
<script>
function sanitizePixelKeyValue(value) {
	var sanitized = (value || '').trim().toLowerCase();
	sanitized = sanitized.replace(/\s+/g, '_');
	sanitized = sanitized.replace(/[^a-z0-9_]/g, '');
	sanitized = sanitized.replace(/_+/g, '_');
	sanitized = sanitized.replace(/^_+|_+$/g, '');
	return sanitized;
}

function sanitizePixelKeyInput(inputEl) {
	if (!inputEl) {
		return;
	}
	inputEl.value = sanitizePixelKeyValue(inputEl.value);
}

function copyToClipboard(inputId, buttonEl) {
	var input = document.getElementById(inputId);
	if (!input) {
		return;
	}
	input.select();
	input.setSelectionRange(0, 99999);
	var originalText = buttonEl.textContent;
	try {
		var copied = false;
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(input.value);
			copied = true;
		} else {
			copied = document.execCommand('copy');
		}
		if (copied) {
			buttonEl.textContent = 'Copied';
			setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
		}
	} catch (e) {
		document.execCommand('copy');
	}
}

function copyTextValue(textValue, buttonEl) {
	var text = (textValue || '').toString();
	if (!text) {
		return;
	}

	var originalText = buttonEl.textContent;
	var copied = false;

	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(text).then(function () {
			buttonEl.textContent = 'Copied!';
			setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
		}).catch(function () {
			buttonEl.textContent = 'Copy failed';
			setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
		});
		return;
	}

	var tempInput = document.createElement('input');
	tempInput.type = 'text';
	tempInput.value = text;
	tempInput.style.position = 'fixed';
	tempInput.style.opacity = '0';
	document.body.appendChild(tempInput);
	tempInput.focus();
	tempInput.select();
	try {
		copied = document.execCommand('copy');
	} catch (e) {
		copied = false;
	}
	document.body.removeChild(tempInput);

	buttonEl.textContent = copied ? 'Copied!' : 'Copy failed';
	setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
}

var pixelKeyInput = document.getElementById('pixel_key');
if (pixelKeyInput) {
	pixelKeyInput.value = sanitizePixelKeyValue(pixelKeyInput.value);
}

function filterPixelRows(term) {
	var query = (term || '').toLowerCase().trim();
	var rows = document.querySelectorAll('tr.pixel-row');
	for (var i = 0; i < rows.length; i++) {
		var row = rows[i];
		var pixelKey = (row.getAttribute('data-pixel-key') || '').toLowerCase();
		var isMatch = query === '' || pixelKey.indexOf(query) !== -1;
		row.style.display = isMatch ? '' : 'none';
	}
}

var pixelSearchInput = document.getElementById('pixel-search');
if (pixelSearchInput) {
	pixelSearchInput.addEventListener('paste', function () {
		var self = this;
		setTimeout(function () {
			filterPixelRows(self.value);
		}, 0);
	});
}
</script>
<?php
render_footer();
