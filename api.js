"use strict";

var path = require("path");
var fs = require("fs");
var getStream = require("get-stream");
var md5 = require("blueimp-md5");
var LRU = require("lru-cache");

var config = require(path.join(__dirname,"config.js"));
var DB = require(path.join(__dirname,"db.js"));

var API = Object.assign(module.exports,{
	handle,
	findChallenge,
});

init();


// *********************************

var challenges;
var accountNumbers;
var usernames;
var profileHashes;
var cachePruneInterval;

function init() {
	challenges = LRU({
		maxAge: 10*60*1000,
	});
	accountNumbers = LRU({
		max: 1E5,
		maxAge: 24*60*60*1000,
	});
	usernames = LRU({
		max: 1E5,
		maxAge: 24*60*60*1000,
	});
	profileHashes = LRU({
		max: 1E5,
		maxAge: 24*60*60*1000,
	});

	cachePruneInterval = setInterval(cleanCache,30*1000);
}

function cleanCache() {
	challenges.prune();
	accountNumbers.prune();
	usernames.prune();
	profileHashes.prune();
}

function findChallenge(val) {
	if (challenges.has(val)) {
		challenges.del(val);
		return true;
	}
	return false;
}

async function handle(req,res) {
	var [,action,val] = req.url.match(/^\/api\/(challenge|lookup-username|lookup-account)(?:\/(.+))?$/);

	// no need to send CSP headers for API responses
	res.removeHeader("Content-Security-Policy");

	if (action == "challenge" && req.method == "GET") {
		let newChallenge;
		do {
			newChallenge = String(Math.trunc(Math.random()*1E10));
		} while (challenges.has(newChallenge));

		challenges.set(newChallenge,true);

		await delay(1000);

		res.writeHead(200,{
			"Content-Type": "application/json",
			"Cache-Control": "private, no-cache, no-store",
		});
		res.end(JSON.stringify({ challenge: newChallenge }));
		return true;
	}
	else if (action == "lookup-username" && req.method == "GET") {
		if (checkAccount(val)) {
			let username;

			// first check the LRU cache
			if (usernames.has(val)) {
				username = usernames.get(val);
			}
			// otherwise pull from the database
			else {
				username = DB.getUsername(val);
			}

			if (username != null) {
				// found username, but not yet in cache?
				if (!usernames.has(val)) {
					usernames.set(val,username);
				}

				res.writeHead(200,{
					"Content-Type": "application/json",
					"Cache-Control": "public, max-age=86400",
				});
				res.end(JSON.stringify({ username }));
				return true;
			}
		}
	}
	else if (action == "lookup-account" && req.method == "GET") {
		if (checkUsername(val)) {
			let account;

			// first check the LRU cache
			if (accounts.has(val)) {
				account = accounts.get(val);
			}
			// otherwise pull from the database
			else {
				account = DB.getAccount(val);
			}

			if (account != null) {
				// found account, but not yet in cache?
				if (!accounts.has(val)) {
					accounts.set(val,account);
				}

				res.writeHead(200,{
					"Content-Type": "application/json",
					"Cache-Control": "public, max-age=86400",
				});
				res.end(JSON.stringify({ account }));
				return true;
			}
		}
	}
}

function generateURL(commitHash) {
	return `${config.HTTPS.AVATAR_IMAGE_CDN}/loop-join/p/${commitHash}/profiles/p.json`;
}

function checkAccount(val) {
	return (
		typeof val == "string" &&
		/^[a-zA-Z0-9\+\/]{64}$/.test(val)
	);
}

function checkUsername(val) {
	return (
		typeof val == "string" &&
		/^[a-z0-9\-_.:]{5,25}$/.test(val)
	);
}

function delay(ms) {
	return new Promise(function c(res){
		setTimeout(res,ms);
	});
}

function localGHUCMirror(commitHash,imageBuf) {
	var hashDir = path.join(config.LOCAL_GHUC_DIR,commitHash);
	fs.mkdirSync(hashDir);
	fs.mkdirSync(path.join(hashDir,"images"));
	fs.writeFileSync(path.join(hashDir,"images","a.jpg"),imageBuf);
}
