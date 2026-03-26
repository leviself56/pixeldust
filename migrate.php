<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

if (!is_installed()) {
	flash('error', 'Install Pixel Dust before running migrations.');
	redirect('install.php');
}

if (!current_admin()) {
	flash('error', 'Admin login required to run migrations.');
	redirect('login.php');
}

$changes = [];
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	try {
		$changes = run_schema_migrations(db());

		if (!$changes) {
			flash('success', 'Schema check complete. No changes required.');
		} else {
			flash('success', 'Migration complete. Applied ' . count($changes) . ' change(s).');
			$_SESSION['migration_changes'] = $changes;
		}
		redirect('migrate.php');
	} catch (Throwable $e) {
		$error = 'Migration failed: ' . $e->getMessage();
	}
}

if (isset($_SESSION['migration_changes']) && is_array($_SESSION['migration_changes'])) {
	$changes = $_SESSION['migration_changes'];
	unset($_SESSION['migration_changes']);
}

$successMsg = flash('success');
$errorMsg = flash('error');

render_header('Schema Migration');
?>
<div class="spaced card">
	<div>
		<h1>Schema Migration</h1>
		<p class="muted">Run schema checks and apply required SQL updates.</p>
	</div>
	<div class="inline">
		<a href="admin/index.php">Back to dashboard</a>
		<a href="logout.php">Logout</a>
	</div>
</div>

<?php if ($successMsg): ?>
	<div class="success"><?php echo e($successMsg); ?></div>
<?php endif; ?>
<?php if ($errorMsg): ?>
	<div class="error"><?php echo e($errorMsg); ?></div>
<?php endif; ?>
<?php if ($error): ?>
	<div class="error"><?php echo e($error); ?></div>
<?php endif; ?>

<div class="card">
	<h2>Run Migration</h2>
	<form method="post">
		<button type="submit">Run Schema Check / Migrate</button>
	</form>
</div>

<?php if ($changes): ?>
	<div class="card">
		<h2>Applied Changes</h2>
		<ul>
			<?php foreach ($changes as $change): ?>
				<li><?php echo e((string) $change); ?></li>
			<?php endforeach; ?>
		</ul>
	</div>
<?php endif; ?>
<?php
render_footer();