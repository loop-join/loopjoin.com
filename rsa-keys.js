"use strict";

var fs = require("fs");
var NodeRSA = require("node-rsa");

var RSAKeys = Object.assign(module.exports,{
	generate,
	extractKeyText,
	normalizeKeyText,
	readKeyFile,
	stripKeyText,
	initKey,
	sign,
	verifySignature,
});


// *******************************

function generate() {
	let key = new NodeRSA({b:2048});
	return extractKeyText(key);
}

function normalizeKeyText(keyText,isPrivateKey = false) {
	keyText = keyText.replace(/^\s+/m,"").replace(/\s+$/m,"");

	// is PKCS1?
	if (/^-----BEGIN RSA/.test(keyText)) {
		let keyType = isPrivateKey ? "private" : "public";
		var key = new NodeRSA(keyText);
		return stripKeyText(key.exportKey(`pkcs8-${keyType}-pem`));
	}
	// already PKCS8 but with headers?
	else if (/^-----BEGIN (?:PUBLIC|PRIVATE)/.test(keyText)) {
		return stripKeyText(keyText);
	}
	// assume already stripped PKCS8
	else {
		return keyText;
	}
}

function extractKeyText(key,pkcs1 = false) {
	var format = pkcs1 ? "pkcs1" : "pkcs8";
	return {
		privateKeyText: stripKeyText(key.exportKey(`${format}-private-pem`)),
		publicKeyText: stripKeyText(key.exportKey(`${format}-public-pem`)),
	};
}

function readKeyFile(keyFilename) {
	var contents = fs.readFileSync(keyFilename);
	return normalizeKeyText( contents.toString() );
}

function stripKeyText(keyText) {
	return keyText
		.replace(/^-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m,"")
		.replace(/^-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m,"")
		.replace(/[\n\r]/g,"");
}

function initKey(keyText,isPrivateKey = false) {
	keyText = normalizeKeyText(keyText,isPrivateKey);
	var keyType = isPrivateKey ? "PRIVATE" : "PUBLIC";
	return new NodeRSA(`-----BEGIN ${keyType} KEY-----\n${keyText}\n-----END ${keyType} KEY-----`);
}

function sign(privateKey,val) {
	return privateKey.sign(val,"base64");
}

function verifySignature(publicKey,val,signature) {
	return publicKey.verify(val,signature,"utf8","base64");
}
