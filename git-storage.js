"use strict";

var path = require("path");
var Git = require("nodegit");

var config = require(path.join(__dirname,"config.js"));
var Mutex = require(path.join(__dirname,"mutex.js"));

var authenticationCallbacks = {
	certificateCheck: function skipCertCheck() { return 1; },
	credentials: onCredentialCheck,
};

var GitStorage = Object.assign(module.exports,{
	saveFile
});

init();


// **************************************

var lockRepo;
var chainedRepo;

async function init() {
	lockRepo = Mutex.create();
	var unlockRepo = lockRepo.lock();
	chainedRepo = await Git.Repository.openBare(config.GIT_DIR);
	unlockRepo();
}

async function saveFile(fileBuf) {
	var unlockRepo = await lockRepo.lock();

	try {
		let commitHash = await replaceAvatarFile(chainedRepo,fileBuf);
		if (!(
			typeof commitHash == "string" &&
			commitHash.length == 40
		)) {
			throw "Commit failed.";
		}

		// await pushRepo(chainedRepo,"origin");

		return commitHash;
	}
	finally {
		unlockRepo();
	}
}

function onCredentialCheck() {
	return Git.Cred.sshKeyNew(
		config.GIT.USERNAME,
		config.GIT.PUBLIC_KEY_PATH,
		config.GIT.PRIVATE_KEY_PATH,
		""
	);
}

async function replaceFile(repo,fileBuf) {
	var HEAD = await repo.getBranchCommit("master");
	var rootTree = await HEAD.getTree();
	var rootTreeBuilder = await Git.Treebuilder.create(repo,rootTree);
	var profilesTree = await rootTree.entryByPath("profiles");
	var profilesBuilder = await Git.Treebuilder.create(repo,profilesTree);

	var fileOID = await Git.Blob.createFromBuffer(repo,fileBuf,fileBuf.length);
	await profilesBuilder.insert("p.json",fileOID,Git.TreeEntry.FILEMODE.BLOB);
	var profilesTreeOID = profilesBuilder.write();
	await rootTreeBuilder.insert("profiles",profilesTreeOID,Git.TreeEntry.FILEMODE.TREE);
	var rootTreeOID = rootTreeBuilder.write();

	var author = Git.Signature.now(config.GIT.PUBLIC_NAME,config.GIT.PUBLIC_EMAIL);

	var commitOID = await repo.createCommit(
		"HEAD",
		author,
		author,
		"adding profile",
		rootTreeOID,
		[HEAD]
	);

	return commitOID.toString();
}

async function pushRepo(repo,toRemote) {
	// temporarily change repo remote URL so it resolves correctly
	await Git.Remote.setUrl(repo,config.GIT.ORIGIN_NAME,config.GIT.NETWORK_ORIGIN);

	var remote = await repo.getRemote(toRemote);

	// get all refs, to push everything
	var refs = await repo.getReferences(Git.Reference.TYPE.LISTALL);
	var refSpecs = refs.map(ref => `${ref.toString()}:${ref.toString()}`);

	var result = await remote.push(refSpecs,{
		callbacks: authenticationCallbacks,
	});

	// reset report remote URL to the one that works from the
	// command line (shell/ssh credentials)
	await Git.Remote.setUrl(repo,config.GIT.ORIGIN_NAME,config.GIT.SHELL_ORIGIN);

	// did push fail?
	if (result !== undefined) {
		throw result;
	}
}
