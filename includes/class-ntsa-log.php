<?php
/**
 * Activity log: who did what, and from which IP.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Activity log.
 */
class NTSA_Log {

	/**
	 * Options whose changes are recorded.
	 *
	 * @var array
	 */
	private static $watched = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'blog_public', 'permalink_structure' );

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ), 10, 1 );
		add_action( 'wp_logout', array( __CLASS__, 'on_logout' ), 10, 1 );
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 10, 1 );
		add_action( 'delete_user', array( __CLASS__, 'on_delete_user' ), 10, 1 );
		add_action( 'set_user_role', array( __CLASS__, 'on_role' ), 10, 3 );
		add_action( 'after_password_reset', array( __CLASS__, 'on_password_reset' ), 10, 1 );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin' ), 10, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_off' ), 10, 1 );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'on_theme' ), 10, 1 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 10, 2 );
		add_action( '_core_updated_successfully', array( __CLASS__, 'on_core' ), 10, 1 );
		add_action( 'updated_option', array( __CLASS__, 'on_option' ), 10, 3 );
		add_action( 'wp_trash_post', array( __CLASS__, 'on_trash' ), 10, 1 );
		add_action( 'before_delete_post', array( __CLASS__, 'on_delete_post' ), 10, 1 );
		add_action( 'wp_ajax_edit-theme-plugin-file', array( __CLASS__, 'on_file_edit' ), 1 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'on_app_password' ), 10, 2 );
		add_action( 'ntsa_settings_saved', array( __CLASS__, 'on_settings' ) );
	}

	/**
	 * Event names for the screen.
	 *
	 * @return array
	 */
	public static function labels() {
		return array(
			'login'           => __( 'Logged in', 'nodethemes-security-ai' ),
			'login_failed'    => __( 'Failed login', 'nodethemes-security-ai' ),
			'logout'          => __( 'Logged out', 'nodethemes-security-ai' ),
			'lockout'         => __( 'IP locked out (too many failed logins)', 'nodethemes-security-ai' ),
			'user_created'    => __( 'User created', 'nodethemes-security-ai' ),
			'user_deleted'    => __( 'User deleted', 'nodethemes-security-ai' ),
			'role_changed'    => __( 'Role changed', 'nodethemes-security-ai' ),
			'password_reset'  => __( 'Password reset', 'nodethemes-security-ai' ),
			'plugin_on'       => __( 'Plugin activated', 'nodethemes-security-ai' ),
			'plugin_off'      => __( 'Plugin deactivated', 'nodethemes-security-ai' ),
			'plugin_deleted'  => __( 'Plugin deleted', 'nodethemes-security-ai' ),
			'plugin_install'  => __( 'Plugin installed', 'nodethemes-security-ai' ),
			'plugin_update'   => __( 'Plugin updated', 'nodethemes-security-ai' ),
			'theme_switch'    => __( 'Theme changed', 'nodethemes-security-ai' ),
			'theme_install'   => __( 'Theme installed', 'nodethemes-security-ai' ),
			'theme_update'    => __( 'Theme updated', 'nodethemes-security-ai' ),
			'core_update'     => __( 'WordPress updated', 'nodethemes-security-ai' ),
			'option_changed'  => __( 'Important setting changed', 'nodethemes-security-ai' ),
			'post_trashed'    => __( 'Moved to trash', 'nodethemes-security-ai' ),
			'post_deleted'    => __( 'Deleted permanently', 'nodethemes-security-ai' ),
			'file_edited'     => __( 'File edited in the WordPress editor', 'nodethemes-security-ai' ),
			'app_password'    => __( 'Application password created', 'nodethemes-security-ai' ),
			'2fa_on'          => __( 'Two-factor login turned on', 'nodethemes-security-ai' ),
			'2fa_off'         => __( 'Two-factor login turned off', 'nodethemes-security-ai' ),
			'2fa_failed'      => __( 'Too many wrong two-factor codes', 'nodethemes-security-ai' ),
			'2fa_backup_used' => __( 'Backup code used', 'nodethemes-security-ai' ),
			'security'        => __( 'Security settings changed', 'nodethemes-security-ai' ),
			'scan'            => __( 'Security scan finished', 'nodethemes-security-ai' ),
		);
	}

	/**
	 * Days the log is kept.
	 *
	 * @return int
	 */
	public static function retention_days() {
		return max( 1, (int) apply_filters( 'ntsa_log_retention', NTSA_FREE_LOG_DAYS ) );
	}

	/**
	 * Most events kept (0 = no limit).
	 *
	 * @return int
	 */
	public static function max_rows() {
		return max( 0, (int) apply_filters( 'ntsa_log_max_rows', NTSA_FREE_LOG_ROWS ) );
	}

	/**
	 * Add an event.
	 *
	 * @param string   $event    Event key.
	 * @param string   $object   What it is about.
	 * @param array    $details  Extra details.
	 * @param int      $severity 1 info, 2 notice, 3 important.
	 * @param int|null $user_id  User (defaults to the current user).
	 */
	public static function add( $event, $object = '', $details = array(), $severity = 1, $user_id = null ) {
		global $wpdb;
		$uid   = null === $user_id ? get_current_user_id() : (int) $user_id;
		$login = '';
		if ( $uid ) {
			$u     = get_userdata( $uid );
			$login = $u ? $u->user_login : '';
		}
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			NTSA_DB::table( 'log' ),
			array(
				'ts'         => time(),
				'user_id'    => $uid,
				'user_login' => substr( $login, 0, 60 ),
				'ip'         => NTSA_IP::get(),
				'event'      => substr( sanitize_key( $event ), 0, 40 ),
				'severity'   => max( 1, min( 3, (int) $severity ) ),
				'object'     => substr( wp_strip_all_tags( (string) $object ), 0, 190 ),
				'details'    => $details ? wp_json_encode( $details ) : null,
			)
		);
		do_action( 'ntsa_log_event', $event, $object, $details, $severity, $uid );
		if ( 0 === wp_rand( 0, 24 ) ) {
			self::trim_rows();
		}
	}

	/**
	 * Keep at most max_rows() events (oldest go first).
	 */
	public static function trim_rows() {
		global $wpdb;
		$max = self::max_rows();
		if ( ! $max ) {
			return;
		}
		$t     = NTSA_DB::table( 'log' );
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $t" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( $count <= $max ) {
			return;
		}
		$cut = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM $t ORDER BY id DESC LIMIT 1 OFFSET %d", $max ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( $cut ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM $t WHERE id <= %d", $cut ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		}
	}

	/**
	 * Read events.
	 *
	 * @param array $args days, limit, offset, event, user, ip, search.
	 * @return array
	 */
	public static function query( $args = array() ) {
		global $wpdb;
		$a     = wp_parse_args(
			$args,
			array(
				'days'   => NTSA_FREE_LOG_DAYS,
				'limit'  => 50,
				'offset' => 0,
				'event'  => '',
				'user'   => '',
				'ip'     => '',
				'search' => '',
			)
		);
		$t     = NTSA_DB::table( 'log' );
		$where = array( $wpdb->prepare( 'ts > %d', time() - (int) $a['days'] * DAY_IN_SECONDS ) );
		if ( '' !== $a['event'] ) {
			$where[] = $wpdb->prepare( 'event = %s', $a['event'] );
		}
		if ( '' !== $a['user'] ) {
			$where[] = $wpdb->prepare( 'user_login = %s', $a['user'] );
		}
		if ( '' !== $a['ip'] ) {
			$where[] = $wpdb->prepare( 'ip = %s', $a['ip'] );
		}
		if ( '' !== $a['search'] ) {
			$like    = '%' . $wpdb->esc_like( $a['search'] ) . '%';
			$where[] = $wpdb->prepare( '(object LIKE %s OR details LIKE %s OR user_login LIKE %s)', $like, $like, $like );
		}
		$w     = implode( ' AND ', $where );
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $t WHERE $w" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $t WHERE $w ORDER BY id DESC LIMIT %d OFFSET %d", (int) $a['limit'], (int) $a['offset'] ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		return array(
			'total' => $total,
			'rows'  => (array) $rows,
		);
	}

	/* ---------------------------------------------------------------------
	 * Event hooks
	 * ------------------------------------------------------------------ */

	/**
	 * Login.
	 *
	 * @param string  $login Username.
	 * @param WP_User $user  User.
	 */
	public static function on_login( $login, $user ) {
		self::add( 'login', '', array(), 1, $user instanceof WP_User ? $user->ID : 0 );
	}

	/**
	 * Failed login: only for existing accounts, at most once per account every 10 minutes
	 * (attacks on made-up usernames are counted by the lockout instead of filling the log).
	 *
	 * @param string $login Username.
	 */
	public static function on_login_failed( $login ) {
		$u = get_user_by( 'login', $login );
		if ( ! $u && is_email( $login ) ) {
			$u = get_user_by( 'email', $login );
		}
		if ( ! $u ) {
			return;
		}
		$k = 'ntsa_lf_' . $u->ID;
		if ( get_transient( $k ) ) {
			return;
		}
		set_transient( $k, 1, 10 * MINUTE_IN_SECONDS );
		self::add( 'login_failed', $u->user_login, array(), user_can( $u, 'manage_options' ) ? 2 : 1, 0 );
	}

	/**
	 * Logout.
	 *
	 * @param int $user_id User.
	 */
	public static function on_logout( $user_id = 0 ) {
		self::add( 'logout', '', array(), 1, (int) $user_id );
	}

	/**
	 * New user.
	 *
	 * @param int $user_id User.
	 */
	public static function on_user_register( $user_id ) {
		$u     = get_userdata( $user_id );
		$roles = $u ? (array) $u->roles : array();
		self::add( 'user_created', $u ? $u->user_login : '#' . $user_id, array( 'roles' => $roles ), in_array( 'administrator', $roles, true ) ? 3 : 1 );
		if ( in_array( 'administrator', $roles, true ) ) {
			do_action( 'ntsa_admin_created', $user_id );
		}
	}

	/**
	 * Deleted user.
	 *
	 * @param int $user_id User.
	 */
	public static function on_delete_user( $user_id ) {
		$u = get_userdata( $user_id );
		self::add( 'user_deleted', $u ? $u->user_login : '#' . $user_id, array(), 2 );
	}

	/**
	 * Role change.
	 *
	 * @param int    $user_id   User.
	 * @param string $role      New role.
	 * @param array  $old_roles Old roles.
	 */
	public static function on_role( $user_id, $role, $old_roles ) {
		if ( empty( $old_roles ) ) {
			return; // New user: already logged as user_created.
		}
		$u = get_userdata( $user_id );
		self::add( 'role_changed', $u ? $u->user_login : '#' . $user_id, array( 'from' => array_values( (array) $old_roles ), 'to' => $role ), 'administrator' === $role ? 3 : 2 );
		if ( 'administrator' === $role ) {
			do_action( 'ntsa_admin_created', $user_id );
		}
	}

	/**
	 * Password reset.
	 *
	 * @param WP_User $user User.
	 */
	public static function on_password_reset( $user ) {
		self::add( 'password_reset', $user->user_login, array(), 2, $user->ID );
	}

	/**
	 * Plugin name from its file.
	 *
	 * @param string $file Plugin file.
	 * @return string
	 */
	private static function plugin_name( $file ) {
		$path = WP_PLUGIN_DIR . '/' . $file;
		if ( is_file( $path ) ) {
			$d = get_file_data( $path, array( 'Name' => 'Plugin Name', 'Version' => 'Version' ) );
			if ( ! empty( $d['Name'] ) ) {
				return $d['Name'] . ( empty( $d['Version'] ) ? '' : ' ' . $d['Version'] );
			}
		}
		return (string) $file;
	}

	/**
	 * Plugin activated.
	 *
	 * @param string $file Plugin.
	 */
	public static function on_plugin( $file ) {
		self::add( 'plugin_on', self::plugin_name( $file ), array(), 2 );
	}

	/**
	 * Plugin deactivated.
	 *
	 * @param string $file Plugin.
	 */
	public static function on_plugin_off( $file ) {
		self::add( 'plugin_off', self::plugin_name( $file ), array(), 2 );
	}

	/**
	 * Plugin deleted.
	 *
	 * @param string $file    Plugin.
	 * @param bool   $deleted Deleted.
	 */
	public static function on_plugin_deleted( $file, $deleted ) {
		if ( $deleted ) {
			self::add( 'plugin_deleted', (string) $file, array(), 2 );
		}
	}

	/**
	 * Theme switched.
	 *
	 * @param string $name Theme name.
	 */
	public static function on_theme( $name ) {
		self::add( 'theme_switch', (string) $name, array(), 2 );
	}

	/**
	 * Installs and updates.
	 *
	 * @param WP_Upgrader $upgrader Upgrader.
	 * @param array       $extra    Details.
	 */
	public static function on_upgrade( $upgrader, $extra ) {
		$type   = isset( $extra['type'] ) ? $extra['type'] : '';
		$action = isset( $extra['action'] ) ? $extra['action'] : '';
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return;
		}
		$event = $type . ( 'install' === $action ? '_install' : '_update' );
		$items = array();
		if ( 'plugin' === $type ) {
			$items = isset( $extra['plugins'] ) ? (array) $extra['plugins'] : ( isset( $extra['plugin'] ) ? array( $extra['plugin'] ) : array() );
			if ( ! $items && 'install' === $action && ! empty( $upgrader->new_plugin_data['Name'] ) ) {
				$items = array( $upgrader->new_plugin_data['Name'] . ' ' . $upgrader->new_plugin_data['Version'] );
			} else {
				$items = array_map( array( __CLASS__, 'plugin_name' ), $items );
			}
		} else {
			$items = isset( $extra['themes'] ) ? (array) $extra['themes'] : ( isset( $extra['theme'] ) ? array( $extra['theme'] ) : array() );
			if ( ! $items && 'install' === $action && ! empty( $upgrader->new_theme_data['Name'] ) ) {
				$items = array( $upgrader->new_theme_data['Name'] . ' ' . $upgrader->new_theme_data['Version'] );
			}
		}
		foreach ( $items as $item ) {
			self::add( $event, (string) $item, array(), 'install' === $action ? 2 : 1 );
		}
	}

	/**
	 * Core updated.
	 *
	 * @param string $version Version.
	 */
	public static function on_core( $version ) {
		self::add( 'core_update', 'WordPress ' . $version, array(), 1 );
	}

	/**
	 * Watched option changed.
	 *
	 * @param string $option Option.
	 * @param mixed  $old    Old.
	 * @param mixed  $value  New.
	 */
	public static function on_option( $option, $old, $value ) {
		if ( ! in_array( $option, self::$watched, true ) || $old === $value ) {
			return;
		}
		$sev = in_array( $option, array( 'siteurl', 'home', 'admin_email' ), true ) || ( 'default_role' === $option && 'administrator' === $value ) ? 3 : 2;
		self::add( 'option_changed', $option, array( 'from' => is_scalar( $old ) ? (string) $old : '', 'to' => is_scalar( $value ) ? (string) $value : '' ), $sev );
	}

	/**
	 * Trash (pages, posts and products only, by logged-in users).
	 *
	 * @param int $post_id Post.
	 */
	public static function on_trash( $post_id ) {
		$p = get_post( $post_id );
		if ( $p && in_array( $p->post_type, array( 'post', 'page', 'product' ), true ) && is_user_logged_in() ) {
			self::add( 'post_trashed', $p->post_type . ': ' . $p->post_title, array( 'id' => (int) $post_id ), 1 );
		}
	}

	/**
	 * Permanent delete.
	 *
	 * @param int $post_id Post.
	 */
	public static function on_delete_post( $post_id ) {
		$p = get_post( $post_id );
		if ( $p && in_array( $p->post_type, array( 'post', 'page', 'product' ), true ) && is_user_logged_in() ) {
			self::add( 'post_deleted', $p->post_type . ': ' . $p->post_title, array( 'id' => (int) $post_id ), 2 );
		}
	}

	/**
	 * File saved in Appearance › Theme File Editor / Plugin File Editor.
	 */
	public static function on_file_edit() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- WordPress checks the nonce right after; we only record the attempt.
		$file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$what = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : ( isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '' );
		// phpcs:enable
		if ( current_user_can( 'edit_themes' ) || current_user_can( 'edit_plugins' ) ) {
			self::add( 'file_edited', trim( $what . ' / ' . $file, ' /' ), array(), 3 );
		}
	}

	/**
	 * Application password created.
	 *
	 * @param int   $user_id User.
	 * @param array $item    Details.
	 */
	public static function on_app_password( $user_id, $item ) {
		$u = get_userdata( $user_id );
		self::add( 'app_password', ( $u ? $u->user_login : '#' . $user_id ) . ' – ' . ( isset( $item['name'] ) ? $item['name'] : '' ), array(), 2 );
	}

	/**
	 * Our own settings changed.
	 */
	public static function on_settings() {
		static $done = false;
		if ( $done || ! is_admin() || ! is_user_logged_in() ) {
			return;
		}
		$done = true;
		self::add( 'security', 'NodeThemes Security AI', array(), 2 );
	}
}
