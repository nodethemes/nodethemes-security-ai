<?php
/**
 * Visitor IP address.
 *
 * Only REMOTE_ADDR cannot be faked by the visitor. Behind Cloudflare or another proxy, the owner
 * picks the header the proxy sets; we never trust forwarded headers by default.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * IP helper.
 */
class NTSA_IP {

	/**
	 * Sources the owner can choose.
	 *
	 * @return array
	 */
	public static function sources() {
		return array(
			'REMOTE_ADDR'           => __( 'Direct connection (REMOTE_ADDR) – default, safest', 'nodethemes-security-ai' ),
			'HTTP_CF_CONNECTING_IP' => __( 'Cloudflare (CF-Connecting-IP)', 'nodethemes-security-ai' ),
			'HTTP_X_REAL_IP'        => __( 'Proxy / load balancer (X-Real-IP)', 'nodethemes-security-ai' ),
			'HTTP_X_FORWARDED_FOR'  => __( 'Proxy / load balancer (X-Forwarded-For, first address)', 'nodethemes-security-ai' ),
		);
	}

	/**
	 * The visitor's IP.
	 *
	 * @return string
	 */
	public static function get() {
		static $ip = null;
		if ( null !== $ip ) {
			return $ip;
		}
		$ip = self::from_server( (string) NTSA_Settings::get( 'ip_source', 'REMOTE_ADDR' ) );
		return $ip;
	}

	/**
	 * Read an IP from one $_SERVER key (falls back to REMOTE_ADDR).
	 *
	 * @param string $source Key.
	 * @return string
	 */
	public static function from_server( $source ) {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		if ( 'REMOTE_ADDR' !== $source && isset( self::sources()[ $source ] ) && ! empty( $_SERVER[ $source ] ) ) {
			$v = sanitize_text_field( wp_unslash( $_SERVER[ $source ] ) );
			$v = trim( explode( ',', $v )[0] );
			if ( filter_var( $v, FILTER_VALIDATE_IP ) ) {
				return $v;
			}
		}
		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
	}

	/**
	 * What each source shows for the current request (to help the owner choose).
	 *
	 * @return array
	 */
	public static function preview() {
		$out = array();
		foreach ( array_keys( self::sources() ) as $k ) {
			$out[ $k ] = isset( $_SERVER[ $k ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $k ] ) ) : '';
		}
		return $out;
	}

	/**
	 * Suggest a source when the site is clearly behind Cloudflare and still uses REMOTE_ADDR.
	 *
	 * @return string Empty when nothing to suggest.
	 */
	public static function suggestion() {
		if ( 'REMOTE_ADDR' !== NTSA_Settings::get( 'ip_source' ) ) {
			return '';
		}
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && ! empty( $_SERVER['HTTP_CF_RAY'] ) ) {
			return 'HTTP_CF_CONNECTING_IP';
		}
		return '';
	}

	/**
	 * Is the current visitor on the allow list?
	 *
	 * @return bool
	 */
	public static function allowed() {
		return ntsa_ip_in_list( self::get(), NTSA_Settings::ip_list( 'fw_allow_ips' ) );
	}
}
