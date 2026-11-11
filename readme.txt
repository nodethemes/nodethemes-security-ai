=== NodeThemes Security AI ===
Contributors: nodethemes
Tags: security, firewall, two-factor, malware scanner, login protection
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress security with a firewall, login limits, two-factor login, a core file check, a malware scan, vulnerability alerts and safe hardening.

== Description ==

NodeThemes Security AI protects WordPress and WooCommerce sites without locking you out of your own site. Every hardening switch is tested right after you turn it on, and a rescue switch in wp-config.php can pause everything if you ever need it.

Included in the free version:

* **Web application firewall** inside WordPress: blocks SQL injection, cross-site scripting, path traversal, PHP code injection, attack tools and scanners, and requests for private files such as .env or wp-config backups, before other plugins and your theme handle the request. Administrators are never blocked, editors may post HTML, and a "Monitor" mode lets you test first. One click turns a rule off for an address after a false alarm. IP allow list and block list.
* **Login protection**: limits failed logins on wp-login.php, the WooCommerce login form and XML-RPC, locks the IP for a while, and locks repeat offenders for longer. Unlock any IP from the dashboard.
* **Strong passwords** for administrators, editors and shop managers (at least 12 characters, three kinds of characters, no username, no common words).
* **Two-factor login (2FA)** with any authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy…), with 10 one-time backup codes. Works with wp-login.php and the WooCommerce My Account login. The free version protects **1 account**.
* **WordPress core file check**: compares every WordPress file with the official checksums from WordPress.org and lists changed, missing and unknown files.
* **Malware scan** of themes, plugins, uploads and the WordPress folder for backdoors, web shells, hidden code, PHP files in uploads and dangerous .htaccess lines. It only reports, it never deletes. The free version runs **1 scan per week**.
* **Known-vulnerability check** of WordPress, plugins and themes against the free WPVulnerability database (off until you turn it on). The free version checks **once a week** and shows the result in the dashboard.
* **Activity log**: logins, failed logins of real accounts, lockouts, new and deleted users, role changes, plugin and theme changes, updates, important settings, file editor saves and application passwords. The free version keeps **7 days and up to 500 events**.
* **Hardening, tested before it stays on**: turn off the file editor, hide the WordPress version, turn off XML-RPC, hide usernames from bots, and generic login error messages.
* **Security checklist** and a dashboard widget that tell you what to do next.

= Free version limits =

* Two-factor login for 1 account
* 1 malware scan per week (files)
* 1 vulnerability check per week
* Activity log: 7 days, up to 500 events
* 5 of the 11 hardening switches

= Optional Pro add-on =

NodeThemes Security AI Pro is a separate add-on sold at [nodethemes.com](https://nodethemes.com/product/nodethemes-security-ai-pro/). It adds an early firewall that runs before WordPress loads, rate limiting, country blocking and your own rules; two-factor login for every user and required 2FA for chosen roles; a file check for all plugins and themes; unlimited and scheduled malware scans including the database; daily vulnerability checks with e-mail and Telegram alerts; a 90-day activity log with search and CSV export; all hardening switches (block PHP in uploads, protect private files, folder listings, security headers, application passwords, table prefix change); WooCommerce checkout protection against card-testing bots; and AI explanations of findings. Pro is installed next to this free plugin, and your settings, logs and scan results stay as they are.

== Installation ==

1. Install the free plugin from [nodethemes.com/free-plugins](https://nodethemes.com/free-plugins/) (Plugins > Add New Plugin > Upload Plugin) and activate it. The firewall and login limits start right away.
2. Open Security AI > Overview and follow the checklist: set up two-factor login for your account, run the core file check and a malware scan, turn on the vulnerability check, and turn on the hardening switches you want.
3. If your site is behind Cloudflare or a proxy, choose the right source in Security AI > Settings > Visitor IP address.

**Rescue:** if you ever cannot log in, add `define( 'NTSA_SAFE_MODE', true );` to wp-config.php. It pauses the firewall, lockouts, two-factor login and the hardening that runs in PHP until you remove the line. `define( 'NTSA_DISABLE_2FA', true );` pauses only two-factor login. Deactivating the plugin removes every rule it added to .htaccess.

**Page cache plugins:** login, checkout and account pages are not cached by standard cache plugins. The firewall only blocks requests that reach PHP.

== Frequently Asked Questions ==

= Can the firewall block real visitors? =

Rarely, for example a visitor who searches for program code. Use Monitor mode first if you are unsure, and "Allow this" in the blocked list turns a rule off for that address. Administrators are never blocked.

= What happens if I lose my phone? =

Use one of your 8-digit backup codes on the code screen. If you have none left, add define( 'NTSA_DISABLE_2FA', true ); to wp-config.php, log in, turn two-factor login off and on again in your profile, then remove the line.

= Does the malware scan delete files? =

No. It reports files and lines that look like malware. Patterns can miss new malware and can flag unusual but harmless code, so every finding shows the file and the matching text for you to judge. You can mark a finding as safe.

= Does it work with WooCommerce? =

Yes. Login limits and two-factor login cover the My Account login, strong passwords cover account details, and the firewall checks checkout requests like any other.

== Privacy ==

The plugin stores, on your own site only: firewall blocks and lockouts (IP address, address requested, browser name), the activity log (username, IP address, what was done) and scan results. They are deleted automatically after the log period, and all of it is removed when you delete the plugin. None of this data is sent to NodeThemes.

== External services ==

This plugin connects to these services:

* **nodethemes.com (update check)**: to check for new versions of this plugin and download them, the plugin sends the plugin's slug and version (and WordPress adds your site address in the user agent) to https://nodethemes.com about twice a day, and when you click "Check again" in Dashboard > Updates. [Terms](https://nodethemes.com/terms/) – [Privacy policy](https://nodethemes.com/privacy-policy/)
* **WordPress.org (core file check)**: only when you click "Check WordPress files now", WordPress's own function asks api.wordpress.org for the official checksums of your WordPress version and language. [Privacy policy](https://wordpress.org/about/privacy/)
* **WPVulnerability (vulnerability check)**: off by default. When you turn it on, the slugs and versions of your installed WordPress, plugins and themes are sent to https://www.wpvulnerability.net once a week and when you click "Check now". No content, users or settings are sent. Data under CC0. [Privacy](https://www.wpvulnerability.com/privacy/) – [License](https://www.wpvulnerability.com/license/)

== Third-party libraries ==

* qrcode-generator 2.0.4 by Kazuhiko Arase, MIT license – https://github.com/kazuhikoarase/qrcode-generator (QR code on the two-factor setup screen; made in your browser, nothing is sent anywhere)

== Changelog ==

= 1.0.0 =
* First release: firewall, login limits and lockouts, strong passwords, two-factor login, WordPress core file check, malware scan, known-vulnerability check, activity log, tested hardening, security checklist and dashboard widget.
