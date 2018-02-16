"use script";

var RSAKeys = (function defineRSA(){
	var webcrypto = (window.crypto && window.crypto.subtle) || undefined;
	// var webcrypto;

	var publicAPI = {
		onReady,
		generate,
		parseFromText,
		sign,
		verify,
	};

	return publicAPI;


	// **************************************

	function onReady() {
		// WebCrypto not available in this browser, so need to load
		// 'jsrsasign' library?
		if (!webcrypto) {
			// let url = "https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/8.0.6/jsrsasign-all-min.js";
			let url = "/js/jsrsasign-all-min.js";
			let script = document.createElement("script");
			script.src = url;
			document.body.appendChild(script);
		}
	}

	async function generate() {
		var privKey, privKeyText, pubKey, pubKeyText;

		if (webcrypto && webcrypto.generateKey) {
			({
				privateKey: privKey,
				publicKey: pubKey,
			} = await webcrypto.generateKey(
				{
					name: "RSASSA-PKCS1-v1_5",
					modulusLength: 2048,
					publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
					hash: { name: "SHA-256" },
				},
				true,
				["sign", "verify"]
			));

			privKeyText = toPem(await webcrypto.exportKey("pkcs8",privKey),/*isPrivateKey=*/true);
			pubKeyText = toPem(await webcrypto.exportKey("spki",pubKey),/*isPrivateKey=*/false);
		}
		else {
			let worker = new Worker("/js/rsa-keys-worker.js");
			worker.postMessage({});

			({
				data: {
					privKeyText,
					pubKeyText
				}
			} = await waitForEvent(worker,"message"));

			worker.terminate();

			privKey = parseFromText(privKeyText);
			pubKey = parseFromText(pubKeyText);
		}

		return {
			privKey, privKeyText,
			pubKey, pubKeyText,
		};
	}

	async function parseFromText(keyText,isPrivateKey = false,length = 2048) {
		if (webcrypto && webcrypto.importKey) {
			let keyFormat = isPrivateKey ? "pkcs8" : "spki";
			let keyTextBuffer = fromPem(keyText);
			let keyUsages = isPrivateKey ? ["sign"] : ["verify"];

			return window.crypto.subtle.importKey(
				keyFormat,
				keyTextBuffer,
				{
					name: "RSASSA-PKCS1-v1_5",
					modulusLength: length,
					publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
					hash: { name: "SHA-256" },
				},
				true,
				keyUsages
			);
		}
		else {
			return KEYUTIL.getKey(keyText);
		}
	}

	async function sign(text,privateKey) {
		if (webcrypto && webcrypto.sign) {
			let textBuffer = Uint8Array.from(text,getCharCode);

			return window.btoa(arrayBufferToString(await webcrypto.sign(
				"RSASSA-PKCS1-v1_5",
				privateKey,
				textBuffer
			)));
		}
		else {
			return hex2b64(privateKey.sign(text,"sha256"));
		}
	}

	async function verify(text,signature,publicKey) {
		if (webcrypto && webcrypto.sign) {
			let signatureBuffer = Uint8Array.from(window.atob(signature),getCharCode);
			let textBuffer = Uint8Array.from(text,getCharCode);

			return webcrypto.verify(
				"RSASSA-PKCS1-v1_5",
				publicKey,
				signatureBuffer,
				textBuffer
			);
		}
		else {
			return publicKey.verify(text,b64tohex(signature));
		}
	}

	function getCharCode(c) { return c.charCodeAt(0); }

	// Adapted From:
	// https://stackoverflow.com/questions/40314257/export-webcrypto-key-to-pem-format/40327542#40327542
	function toPem(keydata,isPrivateKey = false) {
		var keydataS = arrayBufferToString(keydata);
		var keydataB64 = window.btoa(keydataS);
		var keydataB64Pem = formatAsPem(keydataB64,isPrivateKey);
		return keydataB64Pem;
	}

	function fromPem(keydataB64Pem) {
		var keydataB64 = stripPemFormatting(keydataB64Pem);
		var keydataS = window.atob(keydataB64);
		var keydata = Uint8Array.from(keydataS,getCharCode);
		return keydata;
	}

	// Adapted From:
	// https://stackoverflow.com/questions/40314257/export-webcrypto-key-to-pem-format/40327542#40327542
	function arrayBufferToString(buffer) {
		var binary = "";
		var bytes = new Uint8Array(buffer);
		var len = bytes.byteLength;
		for (let i = 0; i < len; i++) {
			binary += String.fromCharCode(bytes[i]);
		}
		return binary;
	}

	// Adapted From:
	// https://stackoverflow.com/questions/40314257/export-webcrypto-key-to-pem-format/40327542#40327542
	function formatAsPem(str,isPrivateKey = false) {
		var keyType = isPrivateKey ? "PRIVATE" : "PUBLIC";

		var finalString = `-----BEGIN ${keyType} KEY-----\n`;

		while (str.length > 0) {
			finalString += str.substring(0, 64) + "\n";
			str = str.substring(64);
		}

		return `${finalString}-----END ${keyType} KEY-----`;
	}

	function stripPemFormatting(str) {
		return str
			.replace(/^-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m,"")
			.replace(/^-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m,"")
			.replace(/[\n\r]/g,"");
	}

	function waitForEvent(elem,evtName) {
		return new Promise(function c(res,rej){
			elem.addEventListener(evtName,function onEvt(arg){
				elem.removeEventListener(evtName,onEvt,false);
				if (evtName == "error") rej(arg);
				else res(arg);
			},false);
		});
	}

})();


document.addEventListener("DOMContentLoaded",RSAKeys.onReady);
