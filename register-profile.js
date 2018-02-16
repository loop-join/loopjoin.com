"use strict";

var path = require("path");
var fs = require("fs");
var md5 = require("blueimp-md5");
var LRU = require("lru-cache");

var config = require(path.join(__dirname,"config.js"));
var API = require(path.join(__dirname,"api.js"));
var DB = require(path.join(__dirname,"db.js"));
var RSAKeys = require(path.join(__dirname,"rsa-keys.js"));

var RegisterProfile = Object.assign(module.exports,{
	handle
});


// *********************************

async function handle(req,res) {
	if (!(await validate(req))) {
		return false;
	}

	var username = req.body["profile-username"].toLowerCase();
	var accountID = req.body["mentocoin-account"] || generateAccountID();

	return { username, accountID };
}

async function validate(req) {
	if (!checkUsername(req.body["profile-username"])) {
		return false;
	}

	// was account provided but invalid?
	if (
		"mentocoin-account" in req.body &&
		!checkAccount(req.body["mentocoin-account"])
	) {
		return false;
	}

	// missing key+challenge+signature data?
	if (!(
		"mentocoin-account-pubkey" in req.body &&
		"mentocoin-account-challenge" in req.body &&
		"mentocoin-account-signature" in req.body
	)) {
		return false;
	}

	// invalid key+challenge+signature data?
	if (!(
		checkPubKey(req.body["mentocoin-account-pubkey"]) &&
		checkChallenge(req.body["mentocoin-account-challenge"]) &&
		checkSignature(req.body["mentocoin-account-signature"])
	)) {
		return false;
	}

	// unknown challenge value?
	if (!API.findChallenge(req.body["mentocoin-account-challenge"])) {
		return false;
	}

	// key+challenge+signature doesn't verify?
	try {
		let pubkey = RSAKeys.initKey(req.body["mentocoin-account-pubkey"],/*isPrivateKey=*/false);
		if (!RSAKeys.verifySignature(
			pubkey,
			req.body["mentocoin-account-challenge"],
			req.body["mentocoin-account-signature"]
		)) {
			return false;
		}
	}
	catch (err) {
		console.log(err);
		return false;
	}

	return true;
}

function generateAccountID() {
	var base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	var id = "";
	for (let i = 0; i < 64; i++) {
		id += base64[Math.trunc(Math.random() * 100) % 64];
	}
	return id;
}

function checkUsername(val) {
	return (
		typeof val == "string" &&
		/^[a-z0-9\-_.:]{5,25}$/i.test(val)
	);
}

function checkAccount(val) {
	return (
		typeof val == "string" &&
		/^[a-zA-Z0-9\+\/]{64}$/.test(val)
	);
}

function checkPubKey(val) {
	val = val.replace(/^\s+/m,"").replace(/\s+$/m,"");

	return (
		typeof val == "string" &&
		/^-----BEGIN (?:RSA )?PUBLIC KEY-----$/m.test(val) &&
		/^-----END (?:RSA )?PUBLIC KEY-----$/m.test(val) &&
		/^[a-zA-Z0-9\+\/\=]{64,}$/.test(RSAKeys.stripKeyText(val))
	);
}

function checkChallenge(val) {
	return (
		typeof val == "string" &&
		/^[0-9]{1,10}$/.test(val)
	);
}

function checkSignature(val) {
	return (
		typeof val == "string" &&
		/^[a-zA-Z0-9\+\/=]{20,}$/.test(val)
	);
}

function delay(ms) {
	return new Promise(function c(res){
		setTimeout(res,ms);
	});
}
