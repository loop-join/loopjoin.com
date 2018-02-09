var path = require("path");
var fs = require("fs");

var DIRS = {
	SECRETS_DIR: path.join("..","secrets"),
	DB_DIR: path.join("..","chained-db"),
	GIT_DIR: path.join("..","chained-repo"),
	STATIC_DIR: path.join(".","static"),
};

var CREDENTIALS = JSON.parse(
	fs.readFileSync(
		path.join(DIRS.SECRETS_DIR,"credentials.json"),
		"utf-8"
	)
);

var DB = {
	PATH: path.join(DIRS.DB_DIR,"chainedlink.db"),
};

var GIT = {
	USERNAME: "git",
	PUBLIC_KEY_PATH: path.join(DIRS.SECRETS_DIR,"github.public.key"),
	PRIVATE_KEY_PATH: path.join(DIRS.SECRETS_DIR,"github.private.key"),
	PUBLIC_NAME: "ChainedLink Admin",
	PUBLIC_EMAIL: "chainedlinksite@gmail.com",
	ORIGIN_NAME: "origin",
	NETWORK_ORIGIN: "git@github.com:chained-link/p.git",
	SHELL_ORIGIN: "git@github.com-chainedlink:chained-link/p.git",
};

var HTTPS = {};

if (process.env.LOCALHOST) {
	Object.assign(HTTPS,{
		SERVER_ADDR: "127.0.0.1",
		SERVER_PORT: 8070,
		SITE_ORIGIN: "localhost",
		STATIC_FILE_CACHE_LENGTH: 1,
		ENFORCE_REDIRECTS: false,
		AVATAR_IMAGE_CDN: "https://localhost:8065",
	});

	HTTPS.SITE_URL = `https://${HTTPS.SITE_ORIGIN}:${HTTPS.SERVER_PORT}`;
}
else {
	Object.assign(HTTPS,{
		SERVER_ADDR: "10.10.10.1",
		SERVER_PORT: 443,
		SITE_ORIGIN: "chained.link",
		STATIC_FILE_CACHE_LENGTH: 86400,
		ENFORCE_REDIRECTS: true,
		AVATAR_IMAGE_CDN: "https://raw.githubusercontent.com",
	});

	HTTPS.SITE_URL = `https://${HTTPS.SITE_ORIGIN}`;
}

Object.assign(HTTPS,{
	SERVER_NAME: "ChainedLink",

	KEY_PATH: path.join(DIRS.SECRETS_DIR,"chainedlink.private.key"),
	CERT_PATH: path.join(DIRS.SECRETS_DIR,"chainedlink.crt"),

	CORS_HEADERS: {
		HEAD: {
			"Access-Control-Allow-Origin": HTTPS.SITE_ORIGIN,
			"Access-Control-Allow-Credentials": false,
			"Access-Control-Allow-Methods": "HEAD, OPTIONS",
			"Access-Control-Allow-Headers": "Accept, Content-Type, User-Agent, X-Requested-With",
		},
		GET: {
			"Access-Control-Allow-Origin": HTTPS.SITE_ORIGIN,
			"Access-Control-Allow-Credentials": false,
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Accept, Content-Type, User-Agent, X-Requested-With",
		},
		POST: {
			"Access-Control-Allow-Origin": HTTPS.SITE_ORIGIN,
			"Access-Control-Allow-Credentials": false,
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Accept, Content-Type, User-Agent, X-Requested-With",
		},
	},

	// API_CORS_HEADERS: {
	// 	"GET": {
	// 		"Access-Control-Allow-Origin": "*",
	// 		"Access-Control-Allow-Credentials": false,
	// 		"Access-Control-Allow-Methods": "GET, OPTIONS",
	// 		"Access-Control-Allow-Headers": "Accept, Content-Type, User-Agent, X-Requested-With",
	// 	},
	// 	"POST": {
	// 		"Access-Control-Allow-Origin": "*",
	// 		"Access-Control-Allow-Credentials": false,
	// 		"Access-Control-Allow-Methods": "POST, OPTIONS",
	// 		"Access-Control-Allow-Headers": "Accept, Content-Type, User-Agent, X-Requested-With",
	// 	},
	// },

	CSP_HEADER: [
		`default-src 'self'`,
		`script-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob: cdnjs.cloudflare.com`,
		`img-src 'self' data: blob: ${HTTPS.AVATAR_IMAGE_CDN.replace(/^https?:\/\//,"")}`,
		`connect-src 'self'`,
		`frame-src 'self' 'unsafe-inline' data: blob:`,
		`worker-src 'self' 'unsafe-inline' data: blob:`,
		`style-src 'self' 'unsafe-inline' data: blob:`,
	].join("; "),

	HSTS_HEADER: `max-age=31536000; includeSubdomains`,
});


// ************************

Object.assign(module.exports,
	DIRS,
	{
		DB,
		GIT,
		HTTPS,
	}
);
