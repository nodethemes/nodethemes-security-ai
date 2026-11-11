/* NodeThemes Security AI – two-factor setup on the profile screen. */
( function ( $ ) {
	'use strict';
	var box = $( '#ntsa-2fa-box' );
	if ( ! box.length || 'undefined' === typeof NTSA2FA ) {
		return;
	}
	var t = NTSA2FA.i18n;
	function post( action, data ) {
		return $.post( NTSA2FA.ajax, $.extend( { action: 'ntsa_2fa_' + action, user: box.data( 'user' ), nonce: box.data( 'nonce' ) }, data || {} ) );
	}
	function fail( r ) {
		var m = r && r.data && r.data.message ? r.data.message : ( r && r.responseJSON && r.responseJSON.data && r.responseJSON.data.message ? r.responseJSON.data.message : t.error );
		window.alert( m ); // Shown only after a click by the user.
	}
	function showCodes( codes ) {
		var el = $( '#ntsa-2fa-codes' ).empty().prop( 'hidden', false );
		$( '<p>' ).text( t.codes ).appendTo( el );
		var pre = $( '<pre style="font-size:16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;display:inline-block;line-height:1.7">' );
		pre.text( codes.join( '\n' ) ).appendTo( el );
	}
	$( '#ntsa-2fa-start' ).on( 'click', function () {
		var btn = $( this ).prop( 'disabled', true );
		post( 'start' ).done( function ( r ) {
			if ( ! r.success ) { btn.prop( 'disabled', false ); return fail( r ); }
			var el = $( '#ntsa-2fa-setup' ).empty().prop( 'hidden', false );
			$( '<p>' ).text( t.scan ).appendTo( el );
			var qr = qrcode( 0, 'M' );
			qr.addData( r.data.uri );
			qr.make();
			$( '<div style="background:#fff;display:inline-block;padding:8px;border:1px solid #e2e8f0;border-radius:8px">' ).html( qr.createSvgTag( 5, 4 ) ).appendTo( el );
			$( '<p><code style="font-size:15px;letter-spacing:.06em"></code></p>' ).find( 'code' ).text( r.data.secret ).end().appendTo( el );
			$( '<p>' ).text( t.enter ).appendTo( el );
			var input = $( '<input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" class="regular-text" style="width:140px;font-size:18px;letter-spacing:.2em">' ).appendTo( el );
			var ok = $( '<button type="button" class="button button-primary" style="margin-left:8px">' ).text( t.confirm ).appendTo( el );
			btn.prop( 'hidden', true );
			ok.on( 'click', function () {
				ok.prop( 'disabled', true );
				post( 'confirm', { code: input.val() } ).done( function ( c ) {
					ok.prop( 'disabled', false );
					if ( ! c.success ) { return fail( c ); }
					el.prop( 'hidden', true );
					showCodes( c.data.codes );
				} ).fail( function ( x ) { ok.prop( 'disabled', false ); fail( x ); } );
			} );
			input.on( 'keydown', function ( e ) { if ( 13 === e.which ) { e.preventDefault(); ok.trigger( 'click' ); } } );
		} ).fail( function ( x ) { btn.prop( 'disabled', false ); fail( x ); } );
	} );
	$( '#ntsa-2fa-backup' ).on( 'click', function () {
		post( 'backup' ).done( function ( r ) { return r.success ? showCodes( r.data.codes ) : fail( r ); } ).fail( fail );
	} );
	$( '#ntsa-2fa-disable' ).on( 'click', function () {
		if ( ! window.confirm( t.sure ) ) { return; }
		post( 'disable' ).done( function ( r ) { return r.success ? window.location.reload() : fail( r ); } ).fail( fail );
	} );
}( jQuery ) );
