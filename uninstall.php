<?php
/**
 * Uninstall: remove settings, logs, scan results, two-factor data and the server rules we added.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

if ( ! defined( 'NTSA_DATA_DIR' ) ) {
	define( 'NTSA_DATA_DIR', WP_CONTENT_DIR . '/nodethemes-security' );
}
require_once __DIR__ . '/includes/class-ntsa-data.php';
require_once ABSPATH . 'wp-admin/includes/misc.php';

// .htaccess rules and the Pro early-firewall lines.
NTSA_Data::remove_prepend();
$ntsa_files = array( ABSPATH . '.htaccess' );
$ntsa_up    = wp_get_upload_dir();
if ( ! empty( $ntsa_up['basedir'] ) ) {
	$ntsa_files[] = trailingslashit( $ntsa_up['basedir'] ) . '.htaccess';
}
foreach ( $ntsa_files as $ntsa_f ) {
	if ( is_file( $ntsa_f ) && is_writable( $ntsa_f ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
		insert_with_markers( $ntsa_f, 'NodeThemes Security AI', array() );
	}
}

// Options and transients.
foreach ( array( 'ntsa_settings', 'ntsa_db_version', 'ntsa_installed', 'ntsa_integrity', 'ntsa_integrity_ok', 'ntsa_malware', 'ntsa_malware_job', 'ntsa_malware_ignored', 'ntsa_malware_last_manual', 'ntsa_vuln', 'ntsa_vuln_last' ) as $ntsa_opt ) {
	delete_option( $ntsa_opt );
}
delete_site_transient( 'ntsa_free_update' );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_ntsa\\_%' OR option_name LIKE '\\_transient\\_timeout\\_ntsa\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// Two-factor data.
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'ntsa\\_2fa\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// Tables.
foreach ( array( 'log', 'fw', 'ip' ) as $ntsa_t ) {
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'ntsa_' . $ntsa_t ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery,WordPress.DB.DirectDatabaseQuery.SchemaChange
}

foreach ( array( 'ntsa_daily', 'ntsa_weekly_vuln', 'ntsa_scan_continue' ) as $ntsa_hook ) {
	wp_clear_scheduled_hook( $ntsa_hook );
}

// Data folder: keep a harmless waf.php if it exists (PHP may still prepend it for a few minutes).
if ( is_dir( NTSA_DATA_DIR ) ) {
	foreach ( (array) glob( NTSA_DATA_DIR . '/*' ) as $ntsa_file ) {
		if ( is_file( $ntsa_file ) && 'waf.php' !== basename( $ntsa_file ) && 'index.php' !== basename( $ntsa_file ) ) {
			wp_delete_file( $ntsa_file );
		}
	}
	if ( is_file( NTSA_DATA_DIR . '/waf.php' ) ) {
		file_put_contents( NTSA_DATA_DIR . '/waf.php', "<?php\n// NodeThemes Security AI was removed. This empty file can be deleted after a few minutes.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	} else {
		wp_delete_file( NTSA_DATA_DIR . '/index.php' );
		wp_delete_file( NTSA_DATA_DIR . '/.htaccess' );
		@rmdir( NTSA_DATA_DIR ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	}
}
