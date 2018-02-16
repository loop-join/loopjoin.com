"use script";

// hacking jsrsasign to work in a webworker
self.window = {};

// importScripts("https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/8.0.6/jsrsasign-all-min.js");
importScripts("/js/jsrsasign-all-min.js");

self.addEventListener("message",function(){
	var key = KEYUTIL.generateKeypair("RSA",2048);
	var privKeyText = KEYUTIL.getPEM(key.prvKeyObj,"PKCS8PRV");
	var pubKeyText = KEYUTIL.getPEM(key.pubKeyObj);

	self.postMessage({
		privKeyText,
		pubKeyText,
	});
});
