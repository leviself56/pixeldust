<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

require_admin();

$currentAdmin = current_admin();
$error = null;
$success = flash('success');

$editingUser = null;
$editId = (int) ($_GET['edit_id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = (string) ($_POST['action'] ?? '');

	try {
		if ($action === 'save_user') {
			$userId = (int) ($_POST['user_id'] ?? 0);
			$username = trim((string) ($_POST['username'] ?? ''));
			$password = (string) ($_POST['password'] ?? '');
			$passwordConfirm = (string) ($_POST['password_confirm'] ?? '');

			if ($username === '') {
				throw new RuntimeException('Username is required.');
			}
			if (strlen($username) < 3) {
				throw new RuntimeException('Username must be at least 3 characters.');
			}

			if ($userId < 1) {
				if ($password === '') {
					throw new RuntimeException('Password is required for new users.');
				}
				if (strlen($password) < 8) {
					throw new RuntimeException('Password must be at least 8 characters.');
				}
				if ($password !== $passwordConfirm) {
					throw new RuntimeException('Password confirmation does not match.');
				}

				$insert = db()->prepare(
					'INSERT INTO pd_admin_users (username, password_hash, created_at)
					 VALUES (:username, :password_hash, NOW())'
				);
				$insert->execute([
					'username' => $username,
					'password_hash' => password_hash($password, PASSWORD_DEFAULT),
				]);

				flash('success', 'User created: ' . $username);
				redirect('users.php');
			}

			if ($password !== '' || $passwordConfirm !== '') {
				if (strlen($password) < 8) {
					throw new RuntimeException('Password must be at least 8 characters.');
				}
				if ($password !== $passwordConfirm) {
					throw new RuntimeException('Password confirmation does not match.');
				}

				$update = db()->prepare(
					'UPDATE pd_admin_users
					 SET username = :username,
					     password_hash = :password_hash
					 WHERE id = :id'
				);
				$update->execute([
					'username' => $username,
					'password_hash' => password_hash($password, PASSWORD_DEFAULT),
					'id' => $userId,
				]);
			} else {
				$update = db()->prepare('UPDATE pd_admin_users SET username = :username WHERE id = :id');
				$update->execute([
					'username' => $username,
					'id' => $userId,
				]);
			}

			flash('success', 'User updated: ' . $username);
			redirect('users.php');
		}

		if ($action === 'delete_user') {
			$userId = (int) ($_POST['user_id'] ?? 0);
			if ($userId < 1) {
				throw new RuntimeException('Invalid user selected.');
			}

			if ($userId === (int) $currentAdmin['id']) {
				throw new RuntimeException('You cannot delete your own account while logged in.');
			}

			$totalAdmins = (int) (db()->query('SELECT COUNT(*) AS total FROM pd_admin_users')->fetch()['total'] ?? 0);
			if ($totalAdmins <= 1) {
				throw new RuntimeException('Cannot delete the last remaining admin user.');
			}

			$delete = db()->prepare('DELETE FROM pd_admin_users WHERE id = :id');
			$delete->execute(['id' => $userId]);

			flash('success', 'User deleted.');
			redirect('users.php');
		}
	} catch (PDOException $e) {
		if ((int) $e->getCode() === 23000 || stripos($e->getMessage(), 'Duplicate entry') !== false) {
			$error = 'Username already exists. Please choose a different username.';
		} else {
			$error = $e->getMessage();
		}
	} catch (Throwable $e) {
		$error = $e->getMessage();
	}
}

if ($editId > 0) {
	$editStmt = db()->prepare('SELECT id, username, created_at, last_login_at FROM pd_admin_users WHERE id = :id LIMIT 1');
	$editStmt->execute(['id' => $editId]);
	$editingUser = $editStmt->fetch();
}

$users = db()->query(
	'SELECT id, username, created_at, last_login_at
	 FROM pd_admin_users
	 ORDER BY id ASC'
)->fetchAll();

render_header('User Management');
?>
<div class="spaced card">
	<div>
		<h1>User Management</h1>
		<p class="muted">Create, edit, and delete admin users.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if ($success): ?>
	<div class="success"><?php echo e($success); ?></div>
<?php endif; ?>
<?php if ($error): ?>
	<div class="error"><?php echo e($error); ?></div>
<?php endif; ?>

<div class="card">
	<h2><?php echo $editingUser ? 'Edit User' : 'Create User'; ?></h2>
	<form method="post">
		<input type="hidden" name="action" value="save_user">
		<input type="hidden" name="user_id" value="<?php echo e((string) ($editingUser['id'] ?? 0)); ?>">
		<div class="row">
			<div>
				<label>Username</label>
				<input type="text" name="username" required minlength="3" value="<?php echo e((string) ($editingUser['username'] ?? '')); ?>">
			</div>
			<div>
				<label>Password <?php echo $editingUser ? '(leave blank to keep current)' : ''; ?></label>
				<input type="password" name="password" <?php echo $editingUser ? '' : 'required'; ?> minlength="8">
			</div>
			<div>
				<label>Confirm Password</label>
				<input type="password" name="password_confirm" <?php echo $editingUser ? '' : 'required'; ?> minlength="8">
			</div>
		</div>
		<p class="inline" style="margin-top:12px;">
			<button type="submit">Save User</button>
			<?php if ($editingUser): ?><a class="nav-btn" href="users.php">Cancel Edit</a><?php endif; ?>
		</p>
	</form>
</div>

<div class="card">
	<h2>Admin Users</h2>
	<table>
		<thead>
		<tr>
			<th>ID</th>
			<th>Username</th>
			<th>Created</th>
			<th>Last Login</th>
			<th>Actions</th>
		</tr>
		</thead>
		<tbody>
		<?php if (!$users): ?>
			<tr><td colspan="5" class="muted">No users found.</td></tr>
		<?php else: ?>
			<?php foreach ($users as $user): ?>
				<tr>
					<td><?php echo e((string) $user['id']); ?></td>
					<td><?php echo e((string) $user['username']); ?><?php echo (int) $user['id'] === (int) $currentAdmin['id'] ? ' (you)' : ''; ?></td>
					<td><?php echo e((string) $user['created_at']); ?></td>
					<td><?php echo e((string) ($user['last_login_at'] ?: '-')); ?></td>
					<td>
						<div class="inline">
							<a class="nav-btn" href="users.php?edit_id=<?php echo (int) $user['id']; ?>">Edit</a>
							<?php if ((int) $user['id'] !== (int) $currentAdmin['id']): ?>
								<form method="post" onsubmit="return confirm('Delete this user?');" style="margin:0;">
									<input type="hidden" name="action" value="delete_user">
									<input type="hidden" name="user_id" value="<?php echo (int) $user['id']; ?>">
									<button type="submit">Delete</button>
								</form>
							<?php endif; ?>
						</div>
					</td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
		</tbody>
	</table>
</div>
<?php
render_footer();
