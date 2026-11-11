<?php
/**
 * Known-vulnerability check for WordPress, plugins and themes.
 *
 * Uses the free WPVulnerability database (https://www.wpvulnerability.com/, data under CC0),
 * which collects reports from CVE, Wordfence, Patchstack, WPScan, JVN and others. Only the names
 * (slugs) and versions of the installed WordPress, plugins and themes are sent; nothing else.
 * The check is off until the site owner turns it on.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Vulnerabilities.
 */
class NTSA_Vuln {

	const RESULT = 'ntsa_vuln';
	const LAST   = 'ntsa_vuln_last';

	/**
	 * API base (can be overridden for testing).
	 *
	 * @return string
	 */
	public static function api() {
		return trailingslashit( defined( 'NTSA_VULN_API' ) ? NTSA_VULN_API : 'https://www.wpvulnerability.net/' );
	}

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'ntsa_weekly_vuln', array( __CLASS__, 'scheduled' ) );
		add_filter( 'cron_schedules', array( __CLASS__, 'schedules' ) );
		if ( NTSA_Settings::get( 'vuln_enabled' ) ) {
			if ( wp_next_scheduled( 'ntsa_weekly_vuln' ) && wp_get_schedule( 'ntsa_weekly_vuln' ) !== self::frequency() ) {
				wp_clear_scheduled_hook( 'ntsa_weekly_vuln' );
			}
			if ( ! wp_next_scheduled( 'ntsa_weekly_vuln' ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, self::frequency(), 'ntsa_weekly_vuln' );
			}
		} elseif ( wp_next_scheduled( 'ntsa_weekly_vuln' ) ) {
			wp_clear_scheduled_hook( 'ntsa_weekly_vuln' );
		}
		// Updates may fix (or bring) vulnerabilities: refresh the list for what changed.
		add_action( 'upgrader_process_complete', array( __CLASS__, 'after_update' ), 20, 0 );
	}

	/**
	 * Weekly schedule.
	 *
	 * @param array $s Schedules.
	 * @return array
	 */
	public static function schedules( $s ) {
		if ( ! isset( $s['weekly'] ) ) {
			$s['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once a week', 'nodethemes-security-ai' ),
			);
		}
		return $s;
	}

	/**
	 * How often (Pro: daily).
	 *
	 * @return string
	 */
	public static function frequency() {
		return (string) apply_filters( 'ntsa_vuln_frequency', 'weekly' );
	}

	/**
	 * May a check run now? (Free: one per NTSA_FREE_VULN_DAYS days.)
	 *
	 * @return bool
	 */
	public static function can_run() {
		if ( 'weekly' !== self::frequency() ) {
			return true;
		}
		return time() - (int) get_option( self::LAST, 0 ) >= NTSA_FREE_VULN_DAYS * DAY_IN_SECONDS;
	}

	/**
	 * What is installed.
	 *
	 * @return array List of array( type, slug, name, version ).
	 */
	public static function inventory() {
		global $wp_version;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$items = array(
			array( 'core', '', 'WordPress', $wp_version ),
		);
		foreach ( get_plugins() as $file => $p ) {
			$slug = false !== strpos( $file, '/' ) ? dirname( $file ) : basename( $file, '.php' );
			if ( 'hello' === $slug ) {
				$slug = 'hello-dolly';
			}
			$items[] = array( 'plugin', $slug, $p['Name'], $p['Version'] );
		}
		foreach ( wp_get_themes() as $slug => $t ) {
			$items[] = array( 'theme', (string) $slug, $t->get( 'Name' ), $t->get( 'Version' ) );
		}
		return $items;
	}

	/**
	 * Ask the database about one item.
	 *
	 * @param string $type    core|plugin|theme.
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @return array|WP_Error Matching vulnerabilities.
	 */
	public static function lookup( $type, $slug, $version ) {
		$url = 'core' === $type ? self::api() . 'core/' . rawurlencode( $version ) . '/' : self::api() . $type . '/' . rawurlencode( $slug ) . '/';
		$key = 'ntsa_vl_' . md5( $url );
		$res = get_transient( $key );
		if ( false === $res ) {
			$r = wp_remote_get(
				$url,
				array(
					'timeout'    => 12,
					'user-agent' => 'NodeThemes-Security-AI/' . NTSA_VERSION . '; ' . home_url( '/' ),
				)
			);
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( 200 !== (int) wp_remote_retrieve_response_code( $r ) ) {
				return new WP_Error( 'ntsa_vuln_http', 'HTTP ' . (int) wp_remote_retrieve_response_code( $r ) );
			}
			$res = json_decode( wp_remote_retrieve_body( $r ), true );
			if ( ! is_array( $res ) ) {
				return new WP_Error( 'ntsa_vuln_json', __( 'Unexpected answer from the vulnerability database.', 'nodethemes-security-ai' ) );
			}
			set_transient( $key, $res, 12 * HOUR_IN_SECONDS );
		}
		if ( ! empty( $res['error'] ) || empty( $res['data']['vulnerability'] ) || ! is_array( $res['data']['vulnerability'] ) ) {
			return array();
		}
		$out = array();
		foreach ( $res['data']['vulnerability'] as $v ) {
			if ( ! self::applies( $v, $version ) ) {
				continue;
			}
			$sev   = isset( $v['impact']['cvss']['severity'] ) ? strtolower( (string) $v['impact']['cvss']['severity'] ) : '';
			$score = isset( $v['impact']['cvss']['score'] ) ? (float) $v['impact']['cvss']['score'] : 0;
			$links = array();
			foreach ( (array) ( isset( $v['source'] ) ? $v['source'] : array() ) as $s ) {
				if ( ! empty( $s['link'] ) && count( $links ) < 3 ) {
					$links[] = array(
						'name' => isset( $s['name'] ) ? sanitize_text_field( (string) $s['name'] ) : '',
						'link' => esc_url_raw( (string) $s['link'] ),
					);
				}
			}
			$out[] = array(
				'name'    => isset( $v['name'] ) ? trim( wp_strip_all_tags( html_entity_decode( (string) $v['name'], ENT_QUOTES, 'UTF-8' ) ) ) : '',
				'sev'     => in_array( $sev, array( 'c', 'h', 'm', 'l', 'n' ), true ) ? $sev : '',
				'score'   => $score,
				'fixed'   => self::fixed_in( $v ),
				'unfixed' => ! empty( $v['operator']['unfixed'] ),
				'links'   => $links,
			);
		}
		return $out;
	}

	/**
	 * Does a vulnerability apply to this version?
	 *
	 * @param array  $v       Vulnerability.
	 * @param string $version Installed version.
	 * @return bool
	 */
	public static function applies( $v, $version ) {
		$o = isset( $v['operator'] ) && is_array( $v['operator'] ) ? $v['operator'] : array();
		if ( '' === (string) $version ) {
			return false;
		}
		$min_ok = true;
		$max_ok = true;
		if ( ! empty( $o['min_operator'] ) && isset( $o['min_version'] ) ) {
			$min_ok = version_compare( $version, (string) $o['min_version'], (string) $o['min_operator'] );
		}
		if ( ! empty( $o['max_operator'] ) && isset( $o['max_version'] ) ) {
			$max_ok = version_compare( $version, (string) $o['max_version'], (string) $o['max_operator'] );
		}
		if ( empty( $o['min_operator'] ) && empty( $o['max_operator'] ) ) {
			return ! empty( $o['unfixed'] ); // No range given: only "not fixed" reports apply to every version.
		}
		return $min_ok && $max_ok;
	}

	/**
	 * First fixed version when the range ends with "below X".
	 *
	 * @param array $v Vulnerability.
	 * @return string
	 */
	private static function fixed_in( $v ) {
		$o = isset( $v['operator'] ) ? $v['operator'] : array();
		if ( ! empty( $o['unfixed'] ) ) {
			return '';
		}
		if ( isset( $o['max_operator'], $o['max_version'] ) && 'lt' === $o['max_operator'] ) {
			return (string) $o['max_version'];
		}
		return '';
	}

	/**
	 * Check everything.
	 *
	 * @param string $by manual|schedule.
	 * @return array|WP_Error
	 */
	public static function run( $by = 'manual' ) {
		if ( ! NTSA_Settings::get( 'vuln_enabled' ) ) {
			return new WP_Error( 'ntsa_vuln_off', __( 'The vulnerability check is off. Turn it on first.', 'nodethemes-security-ai' ) );
		}
		if ( 'manual' === $by && ! self::can_run() ) {
			return new WP_Error( 'ntsa_limit', __( 'The free version checks for vulnerabilities once a week.', 'nodethemes-security-ai' ) );
		}
		update_option( self::LAST, time(), false );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 180 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		$before = self::result();
		$found  = array();
		$errors = 0;
		foreach ( self::inventory() as $it ) {
			$r = self::lookup( $it[0], $it[1], $it[3] );
			if ( is_wp_error( $r ) ) {
				++$errors;
				continue;
			}
			if ( $r ) {
				$found[] = array(
					'type'    => $it[0],
					'slug'    => $it[1],
					'name'    => $it[2],
					'version' => $it[3],
					'vulns'   => $r,
				);
			}
		}
		$res = array(
			'time'    => time(),
			'checked' => count( self::inventory() ),
			'errors'  => $errors,
			'items'   => $found,
		);
		update_option( self::RESULT, $res, false );
		$new = self::new_since( $before, $res );
		if ( $new ) {
			do_action( 'ntsa_vuln_found', $new, $res );
		}
		return $res;
	}

	/**
	 * Items that were not in the previous result.
	 *
	 * @param array $before Old result.
	 * @param array $after  New result.
	 * @return array
	 */
	private static function new_since( $before, $after ) {
		$old = array();
		foreach ( (array) ( isset( $before['items'] ) ? $before['items'] : array() ) as $i ) {
			$old[ $i['type'] . '|' . $i['slug'] . '|' . $i['version'] ] = count( $i['vulns'] );
		}
		$new = array();
		foreach ( $after['items'] as $i ) {
			$k = $i['type'] . '|' . $i['slug'] . '|' . $i['version'];
			if ( ! isset( $old[ $k ] ) || $old[ $k ] < count( $i['vulns'] ) ) {
				$new[] = $i;
			}
		}
		return $new;
	}

	/**
	 * Scheduled run.
	 */
	public static function scheduled() {
		if ( NTSA_Settings::get( 'vuln_enabled' ) ) {
			self::run( 'schedule' );
		}
	}

	/**
	 * After updates, drop items that changed version from the stored result (they will be checked again next time).
	 */
	public static function after_update() {
		$r = self::result();
		if ( empty( $r['items'] ) ) {
			return;
		}
		$now = array();
		foreach ( self::inventory() as $it ) {
			$now[ $it[0] . '|' . $it[1] ] = $it[3];
		}
		$r['items'] = array_values(
			array_filter(
				$r['items'],
				function ( $i ) use ( $now ) {
					$k = $i['type'] . '|' . $i['slug'];
					return isset( $now[ $k ] ) && $now[ $k ] === $i['version'];
				}
			)
		);
		update_option( self::RESULT, $r, false );
	}

	/**
	 * Last result.
	 *
	 * @return array
	 */
	public static function result() {
		$r = get_option( self::RESULT, array() );
		return is_array( $r ) ? $r : array();
	}

	/**
	 * Human severity.
	 *
	 * @param string $s Code.
	 * @return string
	 */
	public static function severity_label( $s ) {
		$m = array(
			'c' => __( 'Critical', 'nodethemes-security-ai' ),
			'h' => __( 'High', 'nodethemes-security-ai' ),
			'm' => __( 'Medium', 'nodethemes-security-ai' ),
			'l' => __( 'Low', 'nodethemes-security-ai' ),
			'n' => __( 'None', 'nodethemes-security-ai' ),
		);
		return isset( $m[ $s ] ) ? $m[ $s ] : __( 'Unknown', 'nodethemes-security-ai' );
	}
}
