<?php
/**
 * File listing helpers for the scans.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Files.
 */
class NTSA_Files {

	/**
	 * Path relative to the WordPress folder.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	public static function rel( $abs ) {
		$root = wp_normalize_path( ABSPATH );
		$abs  = wp_normalize_path( $abs );
		return 0 === strpos( $abs, $root ) ? substr( $abs, strlen( $root ) ) : $abs;
	}

	/**
	 * Absolute path from a relative one (only inside the WordPress folder or wp-content).
	 *
	 * @param string $rel Relative path.
	 * @return string Empty when outside.
	 */
	public static function abs( $rel ) {
		$rel = ltrim( wp_normalize_path( (string) $rel ), '/' );
		if ( false !== strpos( $rel, '../' ) || '' === $rel ) {
			return '';
		}
		$abs = wp_normalize_path( ABSPATH ) . $rel;
		if ( ! file_exists( $abs ) && 0 === strpos( $rel, 'wp-content/' ) ) {
			$abs = wp_normalize_path( WP_CONTENT_DIR ) . substr( $rel, 10 );
		}
		return $abs;
	}

	/**
	 * List files under a folder.
	 *
	 * @param string   $dir     Folder.
	 * @param array    $exts    Extensions to keep (lowercase, no dot). Empty = all.
	 * @param array    $skip    Absolute folders to skip.
	 * @param int      $max     Stop after this many files.
	 * @param bool     $recurse Go into sub-folders.
	 * @param string[] $names   Extra exact file names to keep (e.g. .htaccess).
	 * @return array Absolute paths.
	 */
	public static function walk( $dir, $exts = array(), $skip = array(), $max = 200000, $recurse = true, $names = array() ) {
		$out  = array();
		$dir  = untrailingslashit( wp_normalize_path( $dir ) );
		$skip = array_map(
			function ( $s ) {
				return untrailingslashit( wp_normalize_path( $s ) );
			},
			$skip
		);
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		$stack = array( $dir );
		while ( $stack && count( $out ) < $max ) {
			$d = array_pop( $stack );
			if ( in_array( $d, $skip, true ) ) {
				continue;
			}
			$h = @opendir( $d ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable folders are skipped.
			if ( ! $h ) {
				continue;
			}
			while ( false !== ( $f = readdir( $h ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $f || '..' === $f ) {
					continue;
				}
				$p = $d . '/' . $f;
				if ( is_link( $p ) ) {
					continue;
				}
				if ( is_dir( $p ) ) {
					if ( $recurse ) {
						$stack[] = $p;
					}
					continue;
				}
				$ext = strtolower( pathinfo( $f, PATHINFO_EXTENSION ) );
				if ( ! $exts || in_array( $ext, $exts, true ) || in_array( $f, $names, true ) ) {
					$out[] = $p;
					if ( count( $out ) >= $max ) {
						break;
					}
				}
			}
			closedir( $h );
		}
		return $out;
	}

	/**
	 * Folders of our own plugins (their rule and signature lists would look like malware).
	 *
	 * @return array
	 */
	public static function own_dirs() {
		return array(
			WP_PLUGIN_DIR . '/nodethemes-security-ai',
			WP_PLUGIN_DIR . '/nodethemes-security-ai-pro',
			NTSA_DATA_DIR,
		);
	}
}
