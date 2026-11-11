/* NodeThemes Security AI – admin screens. */
( function ( $ ) {
	'use strict';
	if ( 'undefined' === typeof NTSA ) {
		return;
	}
	var t = NTSA.i18n;
	function call( action, data ) {
		return $.post( NTSA.ajax, $.extend( { action: 'ntsa_' + action, nonce: NTSA.nonce }, data || {} ) );
	}
	function failed( el, r ) {
		var m = r && r.data && r.data.message ? r.data.message : ( r && r.responseJSON && r.responseJSON.data && r.responseJSON.data.message ? r.responseJSON.data.message : t.error );
		el.text( m ).addClass( 'ntsa-bad' );
	}
	function busy( btn, status ) {
		btn.prop( 'disabled', true );
		status.removeClass( 'ntsa-bad' ).text( t.working );
	}

	$( '#ntsa-run-integrity' ).on( 'click', function () {
		var btn = $( this ), st = $( '#ntsa-integrity-status' );
		busy( btn, st );
		call( 'integrity_core' ).done( function ( r ) {
			if ( r.success ) { st.text( t.done ); window.location.reload(); } else { btn.prop( 'disabled', false ); failed( st, r ); }
		} ).fail( function ( x ) { btn.prop( 'disabled', false ); failed( st, x ); } );
	} );

	$( '#ntsa-run-vuln' ).on( 'click', function () {
		var btn = $( this ), st = $( '#ntsa-vuln-status' );
		busy( btn, st );
		call( 'vuln_run' ).done( function ( r ) {
			if ( r.success ) { st.text( t.done ); window.location.reload(); } else { btn.prop( 'disabled', false ); failed( st, r ); }
		} ).fail( function ( x ) { btn.prop( 'disabled', false ); failed( st, x ); } );
	} );

	$( '#ntsa-run-malware' ).on( 'click', function () {
		var btn = $( this ), st = $( '#ntsa-malware-status' ), bar = $( '.ntsa-bar' ).prop( 'hidden', false ), fill = $( '#ntsa-progress' );
		busy( btn, st );
		function show( d ) {
			var pct = d.total ? Math.round( 100 * d.pos / d.total ) : 100;
			fill.css( 'width', pct + '%' );
			st.text( t.scanned.replace( '%1$d', d.pos ).replace( '%2$d', d.total ) );
		}
		function next() {
			call( 'malware_step' ).done( function ( r ) {
				if ( ! r.success ) { btn.prop( 'disabled', false ); return failed( st, r ); }
				if ( r.data.done ) { fill.css( 'width', '100%' ); st.text( t.done ); window.location.reload(); return; }
				show( r.data );
				next();
			} ).fail( function ( x ) { btn.prop( 'disabled', false ); failed( st, x ); } );
		}
		call( 'malware_start' ).done( function ( r ) {
			if ( ! r.success ) { btn.prop( 'disabled', false ); return failed( st, r ); }
			show( r.data );
			next();
		} ).fail( function ( x ) { btn.prop( 'disabled', false ); failed( st, x ); } );
	} );
}( jQuery ) );
