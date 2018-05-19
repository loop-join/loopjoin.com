"use strict";

var path = require("path");
var fs = require("fs");
var getStream = require("get-stream");
var bodyParser = require("urlencoded-body-parser");
var https = require("https");
var staticAlias = require("node-static-alias");
var LRU = require("lru-cache");
var nodeCookie = require("node-cookie");

var config = require(path.join(__dirname,"config.js"));
var API = require(path.join(__dirname,"api.js"));
var RegisterProfile = require(path.join(__dirname,"register-profile.js"));


var fileServer = new staticAlias.Server(config.STATIC_DIR,{
	cache: config.HTTPS.STATIC_FILE_CACHE_LENGTH,
	serverInfo: config.HTTPS.SERVER_NAME,
	gzip: /^\/text/,
	alias: [
		{
			match: /^\/(?:index\/?)?(?:[?#].*$)?$/,
			serve: "index.html",
			force: true,
		},
		{
			match: /^\/(?:(?:(?:css|js|images)\/.+)|(?:robots\.txt|humans\.txt|favicon\.ico))$/,
			serve: "<% absPath %>",
			force: true,
		},
		{
			match: /^\/p\/[a-zA-Z0-9\-_.:]{5,25}\/edit(?:\/|[#?].*)?$/,
			serve: "profile-edit.html",
		},
		{
			match: /^\/p\/[a-zA-Z0-9\-_.:]{5,25}(?:\/|[#?].*)?$/,
			serve: "profile-view.html",
		},
		{
			match: /^\/p\b/,
			serve: "404.html",
		},
		{
			match: /^\/(?:[\w\d]+)(?:[\/?#].*$)?$/,
			serve: function onMatch(params) {
				return `${params.basename}.html`;
			},
		},
		{
			match: /[^]/,
			serve: "404.html",
		},
	],
});

var SESSIONS = LRU({
	maxAge: 10*60*1000,
});

var httpsserv = https.createServer({
	key: fs.readFileSync(config.HTTPS.KEY_PATH),
	cert: fs.readFileSync(config.HTTPS.CERT_PATH),
},handleRequest);

httpsserv.listen(config.HTTPS.SERVER_PORT,config.HTTPS.SERVER_ADDR);

console.log(`Listening on ${config.HTTPS.SERVER_ADDR}:${config.HTTPS.SERVER_PORT}...`);



// **************************

async function handleRequest(req,res) {
	// handle hostname/protocol redirects?
	if (
		config.HTTPS.ENFORCE_REDIRECTS &&
		(
			req.headers["host"] == "www.loopjoin.com" ||
			req.headers["x-forwarded-proto"] !== "https"
		)
	) {
		res.writeHead(301,{ Location: config.HTTPS.SITE_URL });
		res.end();
		return;
	}

	var requestSessionID = nodeCookie.get(req,"SESSIONID");

	res.setHeader("Server",config.HTTPS.SERVER_NAME);

	// From: https://developer.mozilla.org/en-US/docs/Security/CSP/Introducing_Content_Security_Policy
	res.setHeader("Content-Security-Policy",config.HTTPS.CSP_HEADER);

	// From: https://developer.mozilla.org/en-US/docs/Security/HTTP_Strict_Transport_Security
	res.setHeader("Strict-Transport-Security",config.HTTPS.HSTS_HEADER);

	// CORS preflight request for API?
	if (
		req.method == "OPTIONS" &&
		/^\/api\/./.test(req.url) &&
		req.headers["access-control-request-method"] in config.HTTPS.API_CORS_HEADERS
	) {
		res.writeHead(200,config.HTTPS.API_CORS_HEADERS[req.headers["access-control-request-method"]]);
		res.end();
	}
	// CORS preflight request for rest of the site?
	else if (
		req.method == "OPTIONS" &&
		req.headers["access-control-request-method"] in config.HTTPS.CORS_HEADERS
	) {
		res.writeHead(200,config.HTTPS.CORS_HEADERS[req.headers["access-control-request-method"]]);
		res.end();
	}
	// favicon request?
	else if (req.method == "GET" && req.url == "/favicon.ico") {
		// check if favicon exists?
		try {
			fs.statSync(path.join(config.STATIC_DIR,"favicon.ico"));
		}
		// if we get here, favicon is missing
		catch (err) {
			// cacheable empty favicon.ico response
			res.writeHead(204,{
				"Content-Type": "image/x-icon",
				"Cache-Control": "public, max-age: 604800"
			});
			res.end();
			return;
		}

		// otherwise, hand request off to the static file server
		fileServer.serve(req,res);
	}
	// API call?
	else if (
		req.method == "GET" &&
		/^\/api\/./.test(req.url)
	) {
		if (!(await API.handle(req,res))) {
			res.writeHead(403,config.HTTPS.API_CORS_HEADERS.GET);
			res.end();
		}
	}
	// profile registration?
	else if (req.method == "POST" && /^\/register\b/.test(req.url)) {
		req.body = await bodyParser(req,{ limit: 1E4 });

		// set CORS headers
		for (let headerName of Object.keys(config.HTTPS.CORS_HEADERS.POST)) {
			res.setHeader(headerName,config.HTTPS.CORS_HEADERS.POST[headerName]);
		}

		// profile registration failed?
		let result = await RegisterProfile.handle(req,res);
		if (!result) {
			req.method = "GET";
			req.url = "404.html";
			fileServer.serve(req,res);
		}
		else {
			let { username, accountID } = result;
			let sessionID = generateSessionID(username,accountID);
			let location = `${config.HTTPS.SITE_URL}/p/${username}/edit`;

			nodeCookie.create(res,"SESSIONID",sessionID,{
				secure: true,
				sameSite: true,
			});

			res.writeHead(303,{ Location: location });
			res.end();
			return;
		}
	}
	else if (req.method == "GET" && /^\/logout(?:\/|[#?].*)?$/.test(req.url)) {
		// set CORS headers
		for (let headerName of Object.keys(config.HTTPS.CORS_HEADERS.GET)) {
			res.setHeader(headerName,config.HTTPS.CORS_HEADERS.GET[headerName]);
		}

		nodeCookie.clear(res,"SESSIONID");

		res.writeHead(307,{ Location: config.HTTPS.SITE_URL });
		res.end();
		return;
	}
	// hand request off to the static file server?
	else if (["GET","HEAD"].includes(req.method)) {
		// set CORS headers
		for (let headerName of Object.keys(config.HTTPS.CORS_HEADERS.GET)) {
			res.setHeader(headerName,config.HTTPS.CORS_HEADERS.GET[headerName]);
		}

		// check access authorization
		if (!checkSessionAccess(req.url,requestSessionID)) {
			req.url = "404.html";
		}

		fileServer.serve(req,res);
	}
	// otherwise, bail because we won't handle this kind of request!
	else {
		res.writeHead(403,config.HTTPS.CORS_HEADERS.GET);
		res.end();
	}
}

function checkSessionAccess(url,sessionID) {
	if (/^\/p\/[a-zA-Z0-9\-_.:]{5,25}\/edit(?:\/|[#?].*)?$/.test(url)) {
		if (!SESSIONS.has(sessionID)) {
			return false;
		}

		let [,username] = url.match(/^\/p\/([a-zA-Z0-9\-_.:]{5,25})\//);
		let { username: sessionUsername } = SESSIONS.peek(sessionID);

		// session and URL don't match
		if (sessionUsername != username.toLowerCase()) {
			return false;
		}
		else {
			// update session access timestamp
			SESSIONS.get(sessionID);
			return true;
		}
	}

	return true;
}

function generateSessionID(username,accountID) {
	var base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	var id = "";
	do {
		for (let i = 0; i < 64; i++) {
			id += base64[Math.trunc(Math.random() * 100) % 64];
		}
	} while (SESSIONS.has(id));

	SESSIONS.set(id,{ username, accountID });

	return id;
}
