<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

if (!is_installed()) {
	redirect('install.php');
}

if (current_admin()) {
	redirect('admin/index.php');
}

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$username = trim((string) ($_POST['username'] ?? ''));
	$password = (string) ($_POST['password'] ?? '');

	if ($username === '' || $password === '') {
		$error = 'Username and password are required.';
	} else {
		$stmt = db()->prepare('SELECT id, username, password_hash FROM pd_admin_users WHERE username = :username LIMIT 1');
		$stmt->execute(['username' => $username]);
		$admin = $stmt->fetch();

		if (!$admin || !password_verify($password, (string) $admin['password_hash'])) {
			$error = 'Invalid credentials.';
		} else {
			$_SESSION['admin_user_id'] = (int) $admin['id'];

			$update = db()->prepare('UPDATE pd_admin_users SET last_login_at = NOW() WHERE id = :id');
			$update->execute(['id' => (int) $admin['id']]);

			flash('success', 'Welcome back, ' . $admin['username'] . '.');
			redirect('admin/index.php');
		}
	}
}

$successMsg = flash('success');
$errorMsg = flash('error');

render_header('Login');
?>
<div class="card" style="max-width:480px;margin:40px auto;">
	<h1>Pixel Dust Login</h1>
	<p class="muted">Admin access to pixel data and statistics.</p>

	<?php if ($successMsg): ?>
		<div class="success"><?php echo e($successMsg); ?></div>
	<?php endif; ?>
	<?php if ($errorMsg): ?>
		<div class="error"><?php echo e($errorMsg); ?></div>
	<?php endif; ?>
	<?php if ($error): ?>
		<div class="error"><?php echo e($error); ?></div>
	<?php endif; ?>

	<form method="post">
		<p>
			<label>Username</label>
			<input type="text" name="username" required>
		</p>
		<p>
			<label>Password</label>
			<input type="password" name="password" required>
		</p>
		<p><button type="submit">Login</button></p>
	</form>
</div>
<?php
render_footer();
