<?php
/**
 * Database tables, activation and scheduled clean-up.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Tables.
 */
class NTSA_DB {

	const VERSION = '1';

	/**
	 * Table names.
	 *
	 * @param string $t log|fw|ip.
	 * @return string
	 */
	public static function table( $t ) {
		global $wpdb;
		return $wpdb->prefix . 'ntsa_' . $t;
	}

	/**
	 * Create or update the tables.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$c = $wpdb->get_charset_collate();
		dbDelta(
			'CREATE TABLE ' . self::table( 'log' ) . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ts int(10) unsigned NOT NULL,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_login varchar(60) NOT NULL DEFAULT '',
			ip varchar(45) NOT NULL DEFAULT '',
			event varchar(40) NOT NULL DEFAULT '',
			severity tinyint(3) unsigned NOT NULL DEFAULT 1,
			object varchar(190) NOT NULL DEFAULT '',
			details text NULL,
			PRIMARY KEY  (id),
			KEY ts (ts),
			KEY event (event)
			) $c;"
		);
		dbDelta(
			'CREATE TABLE ' . self::table( 'fw' ) . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ts int(10) unsigned NOT NULL,
			ip varchar(45) NOT NULL DEFAULT '',
			action varchar(12) NOT NULL DEFAULT '',
			rule varchar(40) NOT NULL DEFAULT '',
			uri varchar(255) NOT NULL DEFAULT '',
			ua varchar(255) NOT NULL DEFAULT '',
			detail varchar(255) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY ts (ts),
			KEY ip (ip)
			) $c;"
		);
		dbDelta(
			'CREATE TABLE ' . self::table( 'ip' ) . " (
			ip varchar(45) NOT NULL,
			fails int(10) unsigned NOT NULL DEFAULT 0,
			window_start int(10) unsigned NOT NULL DEFAULT 0,
			locked_until int(10) unsigned NOT NULL DEFAULT 0,
			lockouts int(10) unsigned NOT NULL DEFAULT 0,
			lockouts_since int(10) unsigned NOT NULL DEFAULT 0,
			last_user varchar(60) NOT NULL DEFAULT '',
			updated int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (ip),
			KEY locked_until (locked_until)
			) $c;"
		);
		update_option( 'ntsa_db_version', self::VERSION, true );
	}

	/**
	 * Upgrade when the table version changes.
	 */
	public static function maybe_upgrade() {
		if ( get_option( 'ntsa_db_version' ) !== self::VERSION ) {
			self::install();
		}
		add_action( 'ntsa_daily', array( __CLASS__, 'cleanup' ) );
		if ( ! wp_next_scheduled( 'ntsa_daily' ) ) {
			wp_schedule_event( time() + 600, 'daily', 'ntsa_daily' );
		}
	}

	/**
	 * Activation.
	 */
	public static function activate() {
		self::install();
		NTSA_Data::ensure_dir();
		if ( ! wp_next_scheduled( 'ntsa_daily' ) ) {
			wp_schedule_event( time() + 600, 'daily', 'ntsa_daily' );
		}
		if ( ! get_option( 'ntsa_installed' ) ) {
			update_option( 'ntsa_installed', time(), false );
		}
	}

	/**
	 * Deactivation: stop schedules and remove the server rules we added, so nothing of ours
	 * keeps running while the plugin is off. Settings and logs stay for when it is turned on again.
	 */
	public static function deactivate() {
		foreach ( array( 'ntsa_daily', 'ntsa_weekly_vuln', 'ntsa_scan_continue' ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		NTSA_Hardening::remove_server_rules();
		// The .htaccess rules are gone, so these switches are off now (turn them on again after reactivating).
		$state = (array) NTSA_Settings::get( 'hardening', array() );
		foreach ( array( 'uploads_php', 'protect_files', 'no_indexes' ) as $k ) {
			unset( $state[ $k ] );
		}
		NTSA_Settings::update( array( 'hardening' => $state ) );
	}

	/**
	 * Daily clean-up of old rows.
	 */
	public static function cleanup() {
		global $wpdb;
		$keep_days = NTSA_Log::retention_days();
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'log' ) . ' WHERE ts < %d', time() - $keep_days * DAY_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'fw' ) . ' WHERE ts < %d', time() - $keep_days * DAY_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'ip' ) . ' WHERE locked_until < %d AND updated < %d', time(), time() - 2 * DAY_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		NTSA_Log::trim_rows();
	}
}
