"use strict";

var RegisterProfile = (function defineRegister(){
	var registrationForm;
	var profileUsername;
	var registerNewAccountSection;
	var registerLinkAccountBtn;
	var registerLinkAccountSection;
	var mentocoinAccount;
	var registerNewAccountBtn;
	var keyFilePicker;
	var loadPubKeyBtn;
	var mentocoinAccountPublicKey;
	var needNewKeyBtn;
	var mentocoinAccountChallenge;
	var mentocoinAccountSignature;
	var mentocoinAccountSignatureComputeBtn;
	var registerBtn;

	return {
		onReady,
	};


	// *************************

	var challengeRequested;

	function onReady() {
		registrationForm = document.querySelectorAll("[rel*=js-registration-form]")[0];
		profileUsername = document.querySelectorAll("[rel*=js-profile-username]")[0];
		registerNewAccountSection = document.querySelectorAll("[rel*=js-register-new-account]")[0];
		registerLinkAccountBtn = document.querySelectorAll("[rel*=js-link-account-btn]")[0];
		registerLinkAccountSection = document.querySelectorAll("[rel*=js-register-link-account]")[0];
		mentocoinAccount = document.querySelectorAll("[rel*=js-mentocoin-account]")[0];
		registerNewAccountBtn = document.querySelectorAll("[rel*=js-register-new-account-btn]")[0];
		keyFilePicker = document.querySelectorAll("[rel*=js-load-key-picker]")[0];
		loadPubKeyBtn = document.querySelectorAll("[rel*=js-load-pubkey-btn]")[0];
		mentocoinAccountPublicKey = document.querySelectorAll("[rel*=js-mentocoin-account-pubkey]")[0];
		needNewKeyBtn = document.querySelectorAll("[rel*=js-new-key-btn]")[0];
		mentocoinAccountChallenge = document.querySelectorAll("[rel*=js-mentocoin-account-challenge]")[0];
		mentocoinAccountSignature = document.querySelectorAll("[rel*=js-mentocoin-account-signature]")[0];
		mentocoinAccountSignatureComputeBtn = document.querySelectorAll("[rel*=js-compute-signature-btn]")[0];
		registerBtn = document.querySelectorAll("[rel*=js-register-btn]")[0];

		registrationForm.addEventListener("submit",onFormSubmit,false);
		profileUsername.addEventListener("change",usernameEntered,false);
		mentocoinAccount.addEventListener("change",accountEntered,false);
		loadPubKeyBtn.addEventListener("click",pickPublicKeyFile,false);
		mentocoinAccountPublicKey.addEventListener("change",pubkeyEntered,false);
		mentocoinAccountSignature.addEventListener("change",signatureEntered,false);
		registerLinkAccountBtn.addEventListener("click",showLinkAccountControls,false);
		registerNewAccountBtn.addEventListener("click",hideLinkAccountControls,false);
		mentocoinAccountSignatureComputeBtn.addEventListener("click",computeSignature,false);

		challengeRequested = requestChallenge();
	}

	async function onFormSubmit(evt) {
		evt.preventDefault();
		usernameEntered();

		if (!checkRegistrationForm()) {
			if (!validateUsername()) {
				Notification.show("Profile username must be only letters, numbers, or '- _ . :' characters, 5-25 characters in length.",true);
				return;
			}
			else if (!validateAccount()) {
				Notification.show("Enter a valid Account ID, 64 characters in length.",true);
				return;
			}
			else if (!validateKeyAndSignature()) {
				Notification.show("Make sure to enter a valid Public Key and compute the challenge signature from a matching Private Key.",true);
				return;
			}
		}
		else {
			let verified = false;
			try {
				let pubKey = await RSAKeys.parseFromText(mentocoinAccountPublicKey.value,/*isPrivateKey=*/false);
				verified = await RSAKeys.verify(mentocoinAccountChallenge.value,mentocoinAccountSignature.value,pubKey);
			}
			catch (err) {
				console.log(err);
			}

			if (!verified) {
				Notification.show("Signature verification failed. Make sure the Public Key matches the Private Key used to compute the challenge signature.",true);
				return;
			}
		}

		registrationForm.removeEventListener("submit",onFormSubmit,false);
		registrationForm.submit();
	}

	function usernameEntered() {
		profileUsername.value = profileUsername.value.toLowerCase().replace(/[^a-z0-9\-_.:]/g,"");
		checkRegistrationForm();
	}

	function accountEntered() {
		mentocoinAccount.value = mentocoinAccount.value.replace(/^\s+/,"").replace(/\s+$/,"");
		checkRegistrationForm();
	}

	function pubkeyEntered() {
		mentocoinAccountPublicKey.value = mentocoinAccountPublicKey.value.replace(/^\s+/,"").replace(/\s+$/,"");
		checkRegistrationForm();
	}

	function signatureEntered() {
		mentocoinAccountSignature.value = mentocoinAccountSignature.value.replace(/^\s+/,"").replace(/\s+$/,"");
		checkRegistrationForm();
	}

	function checkRegistrationForm() {
		if (
			validateUsername() &&
			validateAccount() &&
			validateKeyAndSignature()
		) {
			registerBtn.disabled = false;
			return true;
		}
		else {
			registerBtn.disabled = true;
			return false;
		}
	}

	function validateUsername() {
		if (profileUsername.value.length <= 5) return false;
		if (profileUsername.value.length >= 25) return false;
		if (/[^a-z0-9\-_.:]/i.test(profileUsername.value)) return false;
		return true;
	}

	function validateAccount() {
		if (!(
			mentocoinAccount.disabled ||
			/^[a-zA-Z0-9\+\/]{64}$/.test(mentocoinAccount.value)
		)) {
			return false;
		}
		return true;
	}

	function validateKeyAndSignature() {
		if (!checkPublicKeyText(mentocoinAccountPublicKey.value)) return false;
		if (!/^[0-9]{1,10}$/.test(mentocoinAccountChallenge.value)) return false;
		if (!/^[a-zA-Z0-9\+\/=]{20,}$/.test(mentocoinAccountSignature.value)) return false;
		return true;
	}

	function checkPublicKeyText(keyText) {
		keyText = keyText.replace(/^\s+/,"").replace(/\s+$/,"");
		if (!(
			/^-----BEGIN (?:RSA )?PUBLIC KEY-----/.test(keyText) &&
			/-----END (?:RSA )?PUBLIC KEY-----$/.test(keyText) &&
			/^[a-zA-Z0-9\+\/\=]{64,}$/.test(stripKeyText(keyText))
		)) {
			return false;
		}
		return true;
	}

	function checkPrivateKeyText(keyText) {
		keyText = keyText.replace(/^\s+/,"").replace(/\s+$/,"");
		if (!(
			/^-----BEGIN (?:RSA )?PRIVATE KEY-----/.test(keyText) &&
			/-----END (?:RSA )?PRIVATE KEY-----$/.test(keyText) &&
			/^[a-zA-Z0-9\+\/\=]{64,}$/.test(stripKeyText(keyText))
		)) {
			return false;
		}
		return true;
	}

	function stripKeyText(keyText) {
		return keyText
			.replace(/^-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m,"")
			.replace(/^-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m,"")
			.replace(/\n/g,"");
	}

	function showLinkAccountControls() {
		registerNewAccountSection.style.display = "none";
		registerLinkAccountSection.style.display = "block";

		mentocoinAccount.disabled = false;
		// TODO: remove this
		mentocoinAccount.value = "aaaaaaaaaabbbbbbbbbbbccccccccccccccdddddddddddddeeeeeeeeeeeee999";

		checkRegistrationForm();

		mentocoinAccount.focus();
	}

	function hideLinkAccountControls() {
		registerNewAccountSection.style.display = "block";
		registerLinkAccountSection.style.display = "none";

		mentocoinAccount.disabled = true;
		mentocoinAccount.value = "";

		checkRegistrationForm();

		registerLinkAccountBtn.focus();
	}

	async function requestChallenge() {
		try {
			mentocoinAccountChallenge.value =
				mentocoinAccountSignature.value = "";
			mentocoinAccountSignatureComputeBtn.disabled =
				mentocoinAccountSignature.disabled = true;
			checkRegistrationForm();

			var response = await fetch(`${window.location.origin.toString()}/api/challenge`,{
				method: "GET",
			});

			response = await response.json();

			if (response && response.challenge &&
				!mentocoinAccountChallenge.disabled
			) {
				mentocoinAccountChallenge.value = response.challenge;
				mentocoinAccountSignatureComputeBtn.disabled =
					mentocoinAccountSignature.disabled = false;
				mentocoinAccountSignature.value = "";
				checkRegistrationForm();
			}

			challengeRequested = null;

			setTimeout(function rerequestChallenge(){
				if (!challengeRequested) {
					challengeRequested = requestChallenge();
				}
			},300*1000);
		}
		catch (err) {
			console.log(err);
			challengeRequested = null;
			mentocoinAccountChallenge.value = "??????????";
			mentocoinAccountSignature.value = "";
			mentocoinAccountSignature.disabled =
				mentocoinAccountSignatureComputeBtn.disabled = true;
			Notification.show("Challenge couldn't be loaded. Try again later.",false,true);
		}
	}

	function pickPublicKeyFile() {
		mentocoinAccountPublicKey.value =
			keyFilePicker.value = "";

		keyFilePicker.addEventListener("change",publicKeyFilePicked,false);
		keyFilePicker.click();
	}

	async function publicKeyFilePicked() {
		try {
			keyFilePicker.removeEventListener("change",publicKeyFilePicked,false);
			mentocoinAccountPublicKey.value = "";

			if (keyFilePicker.files.length > 0) {
				let file = keyFilePicker.files[0];
				let reader = new FileReader();
				reader.readAsText(file);
				await waitForEvent(reader,"loadend");

				keyFilePicker.value = "";

				if (reader.result.length >= 2048) {
					Notification.show("That file is too big.",false,true);
					return;
				}

				var keyText = reader.result.toString().replace(/^\s+/,"").replace(/\s+$/,"");

				if (!checkPublicKeyText(keyText)) {
					Notification.show("That file doesn't look like a valid RSA Public Key. It should be plain text in the standard PEM format.",true);
					return;
				}

				mentocoinAccountPublicKey.value = keyText;
				checkRegistrationForm();

				return;
			}
		}
		catch (err) {
			console.log(err);
		}

		keyFilePicker.value = "";
		Notification.show("Something went wrong loading the RSA Public Key. Please try again.",true);
	}

	function computeSignature() {
		mentocoinAccountSignature.value =
			keyFilePicker.value = "";

		keyFilePicker.addEventListener("change",privateKeyPicked,false);
		keyFilePicker.click();
	}

	async function privateKeyPicked() {
		try {
			keyFilePicker.removeEventListener("change",privateKeyPicked,false);
			mentocoinAccountSignature.value = "";

			if (keyFilePicker.files.length > 0) {
				let file = keyFilePicker.files[0];
				let reader = new FileReader();
				reader.readAsText(file);
				await waitForEvent(reader,"loadend");

				keyFilePicker.value = "";

				if (reader.result.length >= 8192) {
					Notification.show("That file is too big.",false,true);
					return;
				}

				var keyText = reader.result.toString().replace(/^\s+/,"").replace(/\s+$/,"");

				if (!checkPrivateKeyText(keyText)) {
					Notification.show("That doesn't look like a valid RSA Private Key. It should be plain text in the standard PEM (PKCS1 or PKCS8) format.",true);
					return;
				}

				var privKey = await RSAKeys.parseFromText(keyText,/*isPrivateKey=*/true);
				var signature = await RSAKeys.sign(mentocoinAccountChallenge.value,privKey);

				mentocoinAccountSignature.value = signature;
				checkRegistrationForm();

				return;
			}

		}
		catch (err) {
			console.log(err);
		}

		keyFilePicker.value = "";
		Notification.show("Something went wrong loading the RSA Private Key. Please try again.",true);
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


document.addEventListener("DOMContentLoaded",RegisterProfile.onReady);
