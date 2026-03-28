(function () {
	try {
		var current = document.currentScript;
		if (!current || !current.src) {
			return;
		}

		var srcUrl = new URL(current.src, window.location.href);
		var adId = (srcUrl.searchParams.get('id') || '').trim();
		if (!adId) {
			return;
		}

		var endpoint = new URL('ad.php', srcUrl.href);
		endpoint.searchParams.set('id', adId);

		var runtimeScript = document.createElement('script');
		runtimeScript.src = endpoint.toString();
		runtimeScript.async = false;
		(document.head || document.documentElement).appendChild(runtimeScript);
	} catch (e) {
	}
})();
