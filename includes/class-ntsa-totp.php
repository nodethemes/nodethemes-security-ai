<?php
/**
 * Time-based one-time passwords (RFC 6238), the codes shown by Google Authenticator,
 * Microsoft Authenticator, 1Password, Authy and similar apps.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * TOTP.
 */
class NTSA_TOTP {

	const STEP   = 30;
	const DIGITS = 6;

	/**
	 * New random secret (Base32, 160 bits).
	 *
	 * @return string
	 */
	public static function new_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Base32 encode (RFC 4648, no padding).
	 *
	 * @param string $bin Bytes.
	 * @return string
	 */
	public static function base32_encode( $bin ) {
		$alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits  = '';
		foreach ( str_split( $bin ) as $c ) {
			$bits .= str_pad( decbin( ord( $c ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= $alpha[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $s Base32.
	 * @return string
	 */
	public static function base32_decode( $s ) {
		$alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$s     = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $s ) );
		$bits  = '';
		foreach ( str_split( $s ) as $c ) {
			$pos = strpos( $alpha, $c );
			if ( false === $pos ) {
				continue;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * Code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step.
	 * @return string
	 */
	public static function code( $secret, $step ) {
		$key  = self::base32_decode( $secret );
		$msg  = pack( 'N*', 0 ) . pack( 'N*', $step );
		$hash = hash_hmac( 'sha1', $msg, $key, true );
		$off  = ord( substr( $hash, -1 ) ) & 0x0F;
		$num  = ( ( ord( $hash[ $off ] ) & 0x7F ) << 24 ) | ( ( ord( $hash[ $off + 1 ] ) & 0xFF ) << 16 ) | ( ( ord( $hash[ $off + 2 ] ) & 0xFF ) << 8 ) | ( ord( $hash[ $off + 3 ] ) & 0xFF );
		return str_pad( (string) ( $num % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Check a code (allows one step of clock drift either way).
	 *
	 * @param string $secret    Secret.
	 * @param string $code      Code typed by the user.
	 * @param int    $last_step Last step already used (codes can't be reused).
	 * @return int|false The matched step, or false.
	 */
	public static function verify( $secret, $code, $last_step = 0 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( self::DIGITS !== strlen( $code ) || '' === (string) $secret ) {
			return false;
		}
		$now = (int) floor( time() / self::STEP );
		foreach ( array( 0, -1, 1 ) as $d ) {
			$step = $now + $d;
			if ( $step <= (int) $last_step ) {
				continue;
			}
			if ( hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	/**
	 * otpauth:// link for the QR code.
	 *
	 * @param string $secret Secret.
	 * @param string $label  Account label.
	 * @param string $issuer Issuer (site name).
	 * @return string
	 */
	public static function uri( $secret, $label, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $label ) . '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::STEP;
	}
}
