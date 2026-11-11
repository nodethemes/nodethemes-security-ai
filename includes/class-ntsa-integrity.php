<?php
/**
 * File change check for the WordPress core files.
 *
 * Compares every file of WordPress itself with the official checksums from WordPress.org and lists
 * changed, missing and unknown files. (The Pro add-on also checks plugins and themes.)
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Core integrity.
 */
class NTSA_Integrity {

	const OPTION = 'ntsa_integrity';
	const OK     = 'ntsa_integrity_ok';

	/**
	 * Hooks.
	 */
	public static function init() {
		// After a WordPress update the old result no longer applies.
		add_action( '_core_updated_successfully', array( __CLASS__, 'forget_core' ) );
	}

	/**
	 * Last result.
	 *
	 * @return array
	 */
	public static function result() {
		$r = get_option( self::OPTION, array() );
		return is_array( $r ) ? $r : array();
	}

	/**
	 * Forget the core part of the result.
	 */
	public static function forget_core() {
		$r = self::result();
		unset( $r['core'] );
		update_option( self::OPTION, $r, false );
	}

	/**
	 * Official checksums for the installed WordPress.
	 *
	 * @return array|WP_Error path => md5.
	 */
	public static function core_checksums() {
		global $wp_version;
		$pre = apply_filters( 'ntsa_core_checksums', null, $wp_version );
		if ( is_array( $pre ) ) {
			return $pre;
		}
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$sums = get_core_checksums( $wp_version, get_locale() );
		if ( ! is_array( $sums ) && 'en_US' !== get_locale() ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $sums ) || ! $sums ) {
			return new WP_Error( 'ntsa_checksums', __( 'Could not get the official checksums from WordPress.org. Please try again later.', 'nodethemes-security-ai' ) );
		}
		return $sums;
	}

	/**
	 * Files the owner marked as OK (path => md5 at that time).
	 *
	 * @return array
	 */
	public static function ok_list() {
		$v = get_option( self::OK, array() );
		return is_array( $v ) ? $v : array();
	}

	/**
	 * Mark a file as OK (until it changes again).
	 *
	 * @param string $rel Relative path.
	 */
	public static function mark_ok( $rel ) {
		$abs = NTSA_Files::abs( $rel );
		$ok  = self::ok_list();
		if ( '' !== $abs && is_file( $abs ) ) {
			$ok[ $rel ] = md5_file( $abs );
		} else {
			$ok[ $rel ] = 'missing';
		}
		update_option( self::OK, $ok, false );
		$r = self::result();
		foreach ( array( 'core', 'plugins', 'themes' ) as $part ) {
			if ( empty( $r[ $part ] ) ) {
				continue;
			}
			foreach ( array( 'modified', 'missing', 'unknown' ) as $k ) {
				if ( isset( $r[ $part ][ $k ] ) ) {
					$r[ $part ][ $k ] = array_values( array_diff( (array) $r[ $part ][ $k ], array( $rel ) ) );
				}
			}
		}
		update_option( self::OPTION, $r, false );
	}

	/**
	 * Is a file on the OK list with the same content?
	 *
	 * @param string $rel  Relative path.
	 * @param string $hash md5 now ("missing" for missing files).
	 * @return bool
	 */
	public static function is_ok( $rel, $hash ) {
		$ok = self::ok_list();
		return isset( $ok[ $rel ] ) && $ok[ $rel ] === $hash;
	}

	/**
	 * Check the WordPress core files.
	 *
	 * @return array|WP_Error
	 */
	public static function scan_core() {
		global $wp_version;
		$sums = self::core_checksums();
		if ( is_wp_error( $sums ) ) {
			return $sums;
		}
		$root     = wp_normalize_path( ABSPATH );
		$modified = array();
		$missing  = array();
		foreach ( $sums as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue; // Default themes and plugins may be removed or updated: not part of the core check.
			}
			$path = $root . $file;
			if ( ! file_exists( $path ) ) {
				if ( ! self::is_ok( $file, 'missing' ) && ! in_array( $file, array( 'wp-config-sample.php', 'readme.html', 'license.txt' ), true ) ) {
					$missing[] = $file;
				}
				continue;
			}
			$now = md5_file( $path );
			if ( $now !== $md5 && ! self::is_ok( $file, $now ) ) {
				$modified[] = $file;
			}
		}

		// Unknown files inside wp-admin and wp-includes, and unknown PHP files next to wp-config.php.
		$unknown = array();
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( NTSA_Files::walk( $root . $dir, array(), array(), 20000 ) as $abs ) {
				$rel = NTSA_Files::rel( $abs );
				if ( ! isset( $sums[ $rel ] ) && ! self::is_ok( $rel, md5_file( $abs ) ) ) {
					$unknown[] = $rel;
				}
			}
		}
		$allowed_root = apply_filters( 'ntsa_known_root_files', array( 'wp-config.php' ) );
		foreach ( NTSA_Files::walk( $root, array( 'php', 'phtml', 'php5', 'php7', 'phar' ), array(), 500, false ) as $abs ) {
			$rel = NTSA_Files::rel( $abs );
			if ( ! isset( $sums[ $rel ] ) && ! in_array( $rel, $allowed_root, true ) && ! self::is_ok( $rel, md5_file( $abs ) ) ) {
				$unknown[] = $rel;
			}
		}

		$core = array(
			'version'  => $wp_version,
			'checked'  => count( $sums ),
			'modified' => $modified,
			'missing'  => $missing,
			'unknown'  => array_slice( $unknown, 0, 500 ),
		);
		$r           = self::result();
		$r['core']   = $core;
		$r['time']   = time();
		$r['error']  = '';
		update_option( self::OPTION, $r, false );
		$problems = count( $modified ) + count( $missing ) + count( $unknown );
		NTSA_Log::add( 'scan', __( 'WordPress core file check', 'nodethemes-security-ai' ), array( 'problems' => $problems ), $problems ? 3 : 1 );
		if ( $problems ) {
			do_action( 'ntsa_integrity_problems', 'core', $core );
		}
		return $core;
	}

	/**
	 * Total open problems (for the dashboard).
	 *
	 * @return int|null Null when never checked.
	 */
	public static function problem_count() {
		$r = self::result();
		if ( empty( $r['core'] ) ) {
			return null;
		}
		$n = 0;
		foreach ( array( 'core', 'plugins', 'themes' ) as $part ) {
			if ( ! empty( $r[ $part ] ) ) {
				foreach ( array( 'modified', 'missing', 'unknown' ) as $k ) {
					$n += isset( $r[ $part ][ $k ] ) ? count( (array) $r[ $part ][ $k ] ) : 0;
				}
			}
		}
		return $n;
	}
}
