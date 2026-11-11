<?php
/**
 * Firewall rules. This file has no WordPress dependency, so the Pro early firewall can load it
 * before WordPress starts. It only reads the request and returns the first rule that matches.
 *
 * @package NodeThemes_Security_AI
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'NTSA_WAF_EARLY' ) ) {
	exit;
}

if ( ! function_exists( 'ntsa_waf_rules' ) ) {

	/**
	 * The rule list. Each rule: id => array( label, where, pattern ).
	 * "where": q = URL path and query values, p = POST values, a = user agent, u = URL path only.
	 *
	 * @return array
	 */
	function ntsa_waf_rules() {
		return array(
			'sqli-union'   => array( 'SQL injection (UNION SELECT)', 'qp', '/\bunion\b[\s(\/*!]+(?:all[\s(\/*]+|distinct[\s(\/*]+)?select\b/i' ),
			'sqli-time'    => array( 'SQL injection (time delay)', 'qp', '/\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\s+[\'"]/i' ),
			'sqli-schema'  => array( 'SQL injection (database probing)', 'qp', '/\binformation_schema\b|\bmysql\.user\b|\b(?:load_file|into\s+(?:out|dump)file)\s*\(?/i' ),
			'sqli-tauto'   => array( 'SQL injection (always-true condition)', 'q', '/[\'"`)]\s*(?:or|\|\|)\s*[\'"`(]?\s*(\w+)\s*[\'"`)]?\s*=\s*[\'"`(]?\s*\1\b|\b(?:or|and)\s+(\d+)\s*=\s*\2\b/i' ),
			'xss-script'   => array( 'Cross-site scripting (script tag)', 'qp', '/<\s*\/?\s*script\b/i' ),
			'xss-event'    => array( 'Cross-site scripting (event handler)', 'qp', '/<[a-z][^>]*\s(?:on(?:error|load|mouseover|focus|click|toggle|animationstart|pointerover|begin))\s*=/i' ),
			'xss-uri'      => array( 'Cross-site scripting (javascript: link)', 'q', '/(?:^|["\'=(])\s*(?:javascript|vbscript)\s*:\S*[(`]/i' ),
			'traversal'    => array( 'Path traversal', 'qp', '/(?:\.\.[\/\\\\]){2,}|\/etc\/(?:passwd|shadow)\b|proc\/self\/environ|\bwin\.ini\b/i' ),
			'php-wrapper'  => array( 'Remote or PHP file include', 'q', '/^(?:php|data|expect|phar|zip|glob|file):\/\//i' ),
			'php-code'     => array( 'PHP code injection', 'qp', '/<\?php\b|\b(?:eval|assert|passthru|shell_exec|proc_open|popen)\s*\(\s*(?:\$|base64_decode|gzinflate|str_rot13|chr\s*\()/i' ),
			'bad-bot'      => array( 'Attack tool or vulnerability scanner', 'a', '/\b(?:sqlmap|nikto|nmap|masscan|acunetix|netsparker|wpscan|dirbuster|gobuster|nuclei|zgrab|havij|w3af|fimap|openvas|jaeles|feroxbuster)\b/i' ),
			'secret-files' => array( 'Request for a private file', 'u', '/(?:^|\/)(?:wp-config\.php[^\/]+|\.env(?:\.[a-z]+)?|\.git\/.*|\.svn\/.*|\.htpasswd|debug\.log|error_log|\.DS_Store|composer\.lock|phpinfo\.php)$/i' ),
		);
	}

	/**
	 * Decode a value the way an attacker would hide it.
	 *
	 * @param string $v Value.
	 * @return string
	 */
	function ntsa_waf_normalize( $v ) {
		$v = (string) $v;
		for ( $i = 0; $i < 2; $i++ ) {
			$d = rawurldecode( $v );
			if ( $d === $v ) {
				break;
			}
			$v = $d;
		}
		$v = html_entity_decode( $v, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$v = str_replace( "\0", '', $v );
		// SQL comments are often used to hide keywords: UNION/**/SELECT.
		$v = preg_replace( '#/\*.*?\*/#s', ' ', $v );
		return (string) $v;
	}

	/**
	 * Collect the values of a nested array (keys too: attackers put payloads in keys).
	 *
	 * @param mixed $data  Data.
	 * @param array $out   Collected values.
	 * @param int   $depth Depth.
	 */
	function ntsa_waf_flatten( $data, &$out, $depth = 0 ) {
		if ( $depth > 6 || count( $out ) > 400 ) {
			return;
		}
		if ( is_array( $data ) ) {
			foreach ( $data as $k => $v ) {
				if ( is_string( $k ) && '' !== $k ) {
					$out[] = $k;
				}
				ntsa_waf_flatten( $v, $out, $depth + 1 );
			}
			return;
		}
		if ( is_scalar( $data ) && '' !== (string) $data ) {
			$s = (string) $data;
			// Very large fields (file contents, page builders) are not inspected: they are not typical attack vectors and are slow to scan.
			$out[] = strlen( $s ) > 65536 ? substr( $s, 0, 65536 ) : $s;
		}
	}

	/**
	 * Check a request against the rules.
	 *
	 * @param array $req  Keys: path, get (array), post (array), ua (string), json (string, optional raw JSON body).
	 * @param array $opts Keys: skip (rule ids), skip_post (bool), exceptions (array of "rule|path-prefix").
	 * @return array|null array( id, label, value ) of the first match, or null.
	 */
	function ntsa_waf_check( $req, $opts = array() ) {
		$rules      = ntsa_waf_rules();
		$skip       = isset( $opts['skip'] ) ? (array) $opts['skip'] : array();
		$skip_post  = ! empty( $opts['skip_post'] );
		$exceptions = isset( $opts['exceptions'] ) ? (array) $opts['exceptions'] : array();
		$path       = isset( $req['path'] ) ? (string) $req['path'] : '/';

		$q = array();
		ntsa_waf_flatten( isset( $req['get'] ) ? $req['get'] : array(), $q );
		$p = array();
		if ( ! $skip_post ) {
			ntsa_waf_flatten( isset( $req['post'] ) ? $req['post'] : array(), $p );
			if ( ! empty( $req['json'] ) ) {
				$j = json_decode( (string) $req['json'], true );
				if ( is_array( $j ) ) {
					ntsa_waf_flatten( $j, $p );
				}
			}
		}
		$sets = array(
			'u' => array( ntsa_waf_normalize( $path ) ),
			'q' => array_merge( array( ntsa_waf_normalize( $path ) ), array_map( 'ntsa_waf_normalize', $q ) ),
			'p' => array_map( 'ntsa_waf_normalize', $p ),
			'a' => array( isset( $req['ua'] ) ? (string) $req['ua'] : '' ),
		);

		foreach ( $rules as $id => $rule ) {
			if ( in_array( $id, $skip, true ) || ntsa_waf_excepted( $id, $path, $exceptions ) ) {
				continue;
			}
			foreach ( str_split( $rule[1] ) as $where ) {
				foreach ( $sets[ $where ] as $value ) {
					if ( '' !== $value && preg_match( $rule[2], $value ) ) {
						return array( $id, $rule[0], substr( $value, 0, 200 ) );
					}
				}
			}
		}
		return null;
	}

	/**
	 * Is a rule switched off for this path (by the site owner)?
	 *
	 * @param string $id         Rule id.
	 * @param string $path       URL path.
	 * @param array  $exceptions "rule|/path/prefix" strings.
	 * @return bool
	 */
	function ntsa_waf_excepted( $id, $path, $exceptions ) {
		foreach ( $exceptions as $ex ) {
			$parts = explode( '|', (string) $ex, 2 );
			if ( 2 !== count( $parts ) ) {
				continue;
			}
			if ( ( $parts[0] === $id || '*' === $parts[0] ) && ( '' === $parts[1] || 0 === strpos( $path, $parts[1] ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is an IP in a list of IPs and CIDR ranges?
	 *
	 * @param string $ip   IP.
	 * @param array  $list IPs / CIDRs.
	 * @return bool
	 */
	function ntsa_ip_in_list( $ip, $list ) {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input is expected.
		if ( false === $bin ) {
			return false;
		}
		foreach ( (array) $list as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( false === strpos( $entry, '/' ) ) {
				if ( @inet_pton( $entry ) === $bin ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					return true;
				}
				continue;
			}
			list( $net, $bits ) = explode( '/', $entry, 2 );
			$nbin = @inet_pton( $net ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$bits = (int) $bits;
			if ( false === $nbin || strlen( $nbin ) !== strlen( $bin ) || $bits < 0 || $bits > strlen( $bin ) * 8 ) {
				continue;
			}
			$bytes = intdiv( $bits, 8 );
			if ( substr( $bin, 0, $bytes ) !== substr( $nbin, 0, $bytes ) ) {
				continue;
			}
			$rest = $bits % 8;
			if ( 0 === $rest ) {
				return true;
			}
			$mask = chr( ( 0xff << ( 8 - $rest ) ) & 0xff );
			if ( ( $bin[ $bytes ] & $mask ) === ( $nbin[ $bytes ] & $mask ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Send the "blocked" page and stop.
	 *
	 * @param string $ref  Short reference shown to the visitor.
	 * @param int    $code HTTP status.
	 */
	function ntsa_waf_block_page( $ref, $code = 403 ) {
		if ( ! headers_sent() ) {
			http_response_code( (int) $code );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex' );
		}
		$ref = htmlspecialchars( (string) $ref, ENT_QUOTES, 'UTF-8' );
		echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Request blocked</title></head>'
			. '<body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f8fafc;color:#0f172a;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:16px;box-sizing:border-box">'
			. '<div style="max-width:520px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px">'
			. '<h1 style="font-size:22px;margin:0 0 10px">Request blocked</h1>'
			. '<p style="line-height:1.6;margin:0 0 10px">This request was blocked by the site&#8217;s security firewall because it looked like an attack.</p>'
			. '<p style="line-height:1.6;margin:0;color:#475569">If you think this is a mistake, please contact the site owner and mention this reference: <code>' . $ref . '</code></p>'
			. '</div></body></html>';
		exit;
	}
}
