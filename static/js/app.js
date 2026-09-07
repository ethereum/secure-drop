// Function to display error messages
function showError(message) {
	const errorDiv = document.getElementById('error-message');
	if (errorDiv) {
		errorDiv.innerHTML = message;
		errorDiv.style.display = 'block';
		// Auto-hide after 10 seconds
		setTimeout(() => {
			errorDiv.style.display = 'none';
		}, 10000);
	} else {
		// Fallback to alert if error div doesn't exist
		alert(message);
	}
}

// Function to hide error messages
function hideError() {
	const errorDiv = document.getElementById('error-message');
	if (errorDiv) {
		errorDiv.style.display = 'none';
	}
}

Dropzone.options.dropzoneArea = {
	maxFilesize: 20, // Max file size per file in MB
	maxFiles: 10, // Max number of files
	url: '/fake',
	paramName: 'attachment',
	autoProcessQueue: false,
	autoQueue: false,
	addRemoveLinks: true,
	uploadMultiple: true,
	dictDefaultMessage: 'Drag & drop your files here - or click to browse. You can attach multiple files, up to a total of 20MB.',
	dictFileTooBig: 'File is too big ({{filesize}}MB). Max filesize: {{maxFilesize}}MB.',
	dictMaxFilesExceeded: 'You can only upload a maximum of {{maxFiles}} files.',
	init: function() {
		var dropzone = this;
		
		this.on("addedfile", function(file) {
			hideError(); // Clear any existing errors
			
			// Check individual file size
			if (file.size > 20 * 1024 * 1024) {
				this.removeFile(file);
				showError(`Error: File "${file.name}" is too large (${(file.size / 1024 / 1024).toFixed(2)}MB). Maximum file size is 20MB.`);
				return;
			}
			
			// Calculate the total added file size
			var totalSize = this.files.reduce(function(total, f) {
				return total + f.size;
			}, 0);
			
			// If the total added file size is greater than 20 MB, remove the file
			if (totalSize > 20 * 1024 * 1024) {
				this.removeFile(file);
				showError(`Error: Total file size would exceed the 20MB limit. Current total: ${(totalSize / 1024 / 1024).toFixed(2)}MB`);
			}
		});
		
		this.on("maxfilesexceeded", function(file) {
			this.removeFile(file);
			showError(`Error: You can only upload a maximum of ${this.options.maxFiles} files.`);
		});
		
		this.on("removedfile", function(file) {
			hideError(); // Clear errors when file is removed
			// Calculate the total added file size
			var totalSize = this.files.reduce(function(total, f) {
				return total + f.size;
			}, 0);
			
			// Log the total added file size
			console.log("Total file size: " + (totalSize / 1024 / 1024).toFixed(2) + "MB");
		});
		
		this.on("error", function(file, errorMessage) {
			this.removeFile(file);
			showError(`Error: ${errorMessage}`);
		});
	}
};

// zkPassport passport verification (optional, legal submissions only).
// The proof is held in memory until submit; the server verifies it.
var passportProof = null;   // { proofs, queryResult } once the phone has produced a proof
var passportStatus = null;  // "failed" | "unavailable" after an attempt that did not produce one
var passportAttempt = 0;    // increments per click; callbacks from older attempts are ignored
var zkPassportInstance = null;
const PASSPORT_FIELDS = ["fullname", "firstname", "lastname", "birthdate", "nationality",
	"gender", "document_number", "expiry_date", "issuing_country", "document_type"];

function setPassportStatus(text) {
	document.getElementById("passport-status").textContent = text;
}

async function startPassportVerification() {
	const section = document.getElementById("passport-section");
	const button = document.getElementById("verify-passport");
	const panel = document.getElementById("passport-panel");
	const qrContainer = document.getElementById("zkpassport-qr");
	const link = document.getElementById("zkpassport-link");
	const attempt = ++passportAttempt;
	if (zkPassportInstance) {
		zkPassportInstance.clearAllRequests(); // drop the previous attempt's connection and callbacks
	}
	passportProof = null;
	passportStatus = null;
	button.disabled = true;
	panel.style.display = "block";
	qrContainer.innerHTML = "";
	link.style.display = "none";
	setPassportStatus("Preparing your request...");

	try {
		const zk = new ZKPassport(section.dataset.domain);
		zkPassportInstance = zk;
		let query = await zk.request({
			name: "Ethereum Foundation Secure Drop",
			logo: location.origin + "/static/img/eth-diamond2x.png",
			purpose: "Verify your passport for EF onboarding. Only the listed fields are shared with EF Legal.",
			scope: section.dataset.scope,
			returnDeepLink: location.href
		});
		for (const field of PASSPORT_FIELDS) {
			query = query.disclose(field);
		}
		query = query.eq("document_type", "passport");
		if (section.dataset.facematch !== "off") {
			query = query.facematch(section.dataset.facematch);
		}
		const request = query.done();
		if (attempt !== passportAttempt) return; // superseded while the request was being prepared

		const qr = qrcode(0, "M");
		qr.addData(request.url);
		qr.make();
		qrContainer.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2 });
		link.href = request.url;
		link.style.display = "inline";
		setPassportStatus("Scan the code with the zkPassport app, or open the link on your phone.");

		const current = (fn) => (...args) => { if (attempt === passportAttempt) fn(...args); };
		request.onRequestReceived(current(() => setPassportStatus("Request received. Follow the steps on your phone.")));
		request.onGeneratingProof(current(() => setPassportStatus("Generating the proof on your phone. This can take a minute.")));
		request.onSuccess(current(({ proofs, result }) => {
			passportProof = { proofs: proofs, queryResult: result };
			passportStatus = null;
			qrContainer.innerHTML = "";
			link.style.display = "none";
			setPassportStatus("Passport proof ready. It will be verified when you submit.");
			button.textContent = "Start over";
			button.disabled = false;
		}));
		request.onReject(current(() => passportAttemptFailed("The request was declined in the app. You can try again, or upload a photo of your passport instead.")));
		request.onError(current(() => passportAttemptFailed("The app did not complete the proof. You can try again, or upload a photo of your passport instead.")));
	} catch (error) {
		console.error(error);
		if (attempt === passportAttempt) {
			passportAttemptFailed("Passport verification could not start. You can try again, or upload a photo of your passport instead.");
		}
	}
}

// The verifier could not be reached. The proof is kept so a plain resubmit
// retries it; only a real rejection discards it.
function passportServiceUnavailable(message) {
	setPassportStatus(message);
	document.getElementById("passport-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Forget everything about the passport step, e.g. when the recipient changes.
function resetPassportState() {
	passportAttempt++;
	if (zkPassportInstance) {
		zkPassportInstance.clearAllRequests();
	}
	passportProof = null;
	passportStatus = null;
	document.getElementById("passport-panel").style.display = "none";
	document.getElementById("zkpassport-qr").innerHTML = "";
	setPassportStatus("");
	const button = document.getElementById("verify-passport");
	button.textContent = "Verify passport with zkPassport";
	button.disabled = false;
}

function passportAttemptFailed(message, status) {
	passportProof = null;
	passportStatus = status || "failed";
	document.getElementById("zkpassport-qr").innerHTML = "";
	document.getElementById("zkpassport-link").style.display = "none";
	setPassportStatus(message);
	document.getElementById("passport-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
	const button = document.getElementById("verify-passport");
	button.textContent = "Try again";
	button.disabled = false;
}

var dataArray;
function acceptEncryptedData(data) {
	if (data.name == 'message') {
		dataArray['message'] = data.data;
	}
	else {
		dataArray.files.push({'filename': data.name, 'attachment': data.data});
	}
	dataArray.receivedChunks++;

	if (dataArray.receivedChunks == dataArray.requiredChunks) {
		console.log('all chunks received, submitting form');
		const cfTurnstileBlock = document.getElementById('cfTurnstile');
		const recipient = document.getElementById("recipientSelect");
		const reference = document.getElementById("reference");

		dataArray['cf-turnstile-response'] = cfTurnstileBlock ? turnstile.getResponse() : null;
		dataArray['recipient'] = recipient.value;
		dataArray['reference'] = reference.value;
		if (passportProof) {
			dataArray['passport'] = passportProof;
		} else if (passportStatus) {
			dataArray['passportStatus'] = passportStatus;
		}

		postData('/submit-encrypted-data', dataArray)
		.then(response => {
			console.log(response.status, response.code || '');
			if (response.code === "verification_unavailable") {
				// Keep the form and the proof; a resubmit retries the verifier.
				if (!passportProof) passportStatus = "unavailable";
				passportServiceUnavailable(response.message);
				turnstile.reset();
				return;
			}
			displayResult(response.status, response.message)
		})
		.catch(error => {
			console.error(error);
			displayResult('error', 'An error occurred while submitting the form. Please try again later.')
		});
	}
}

document.addEventListener('DOMContentLoaded', function() {
	var text = document.getElementById("text");
	var recipient = document.getElementById("recipientSelect");
	var recipientLabel = document.getElementById("recipientLabel");
	var messageLabel = document.getElementById("messageLabel");

	text.focus();

	// We can have recipient set in the URL
	const params = new URLSearchParams(window.location.search);
	const name = params.get("recipient");
	if(name && name != "") {
		recipient.value = name;
		recipient.style.visibility = 'hidden';
		recipientLabel.style.visibility = 'hidden';
	};

	// Handle reference field visibility based on recipient
	recipient.addEventListener("change", function() {
		const referenceContainer = document.getElementById("referenceContainer");
		const referenceInput = document.getElementById("reference");
		
		if (recipient.value === "security") {
			// Hide reference field for Security
			referenceContainer.style.display = "none";
			referenceInput.removeAttribute("required");
			referenceInput.value = ""; // Clear the value
		} else {
			// Show reference field for Legal and Devcon
			referenceContainer.style.display = "block";
			referenceInput.setAttribute("required", "required");
		}

		// Passport verification is offered to Legal only; leaving Legal forgets any proof
		document.getElementById("passport-section").style.display = recipient.value === "legal" ? "block" : "none";
		if (recipient.value !== "legal") {
			resetPassportState();
		}
	});

	document.getElementById("verify-passport").addEventListener("click", startPassportVerification);
	
	// Trigger change event on page load to set initial state
	recipient.dispatchEvent(new Event('change'));

	// Multi file upload meets encryption
	document.forms[0].addEventListener("submit", function(evt) {
		evt.preventDefault();
		hideError(); // Clear any existing errors
		
		// Validate form before submission
		const selectedFiles = Dropzone.instances[0].files || [];
		
		// Check if reference is required and empty
		const referenceInput = document.getElementById("reference");
		const recipient = document.getElementById("recipientSelect");
		if (recipient.value !== "security" && !referenceInput.value.trim()) {
			showError("Error: Please enter a Reference ID before submitting.");
			referenceInput.focus();
			return false;
		}
		
		// Check number of files
		if (selectedFiles.length > 10) {
			showError(`Error: Too many files selected. You can only upload a maximum of 10 files. Currently selected: ${selectedFiles.length}`);
			return false;
		}
		
		// Check total file size
		const totalSize = selectedFiles.reduce(function(total, file) {
			return total + file.size;
		}, 0);
		
		if (totalSize > 20 * 1024 * 1024) {
			showError(`Error: Total file size exceeds the 20MB limit. Current total: ${(totalSize / 1024 / 1024).toFixed(2)}MB`);
			return false;
		}
		
		// Check individual file sizes
		for (let i = 0; i < selectedFiles.length; i++) {
			if (selectedFiles[i].size > 20 * 1024 * 1024) {
				showError(`Error: File "${selectedFiles[i].name}" is too large (${(selectedFiles[i].size / 1024 / 1024).toFixed(2)}MB). Maximum file size is 20MB.`);
				return false;
			}
		}
		
		captchaExpired(); // disable the submit button this way to prevent double submission
		
		dataArray = { message: '', files: [], requiredChunks: selectedFiles.length+1, receivedChunks: 0 };

		encrypt(text.value).then(acceptEncryptedData);
		
		for (var i=0; i < selectedFiles.length; i++) {
			let current_file = selectedFiles[i];

			var reader = new FileReader();
			reader.addEventListener('load', (event) => {
				var arrayBuffer = event.target.result;
				var fileData = new Uint8Array(arrayBuffer);
				encryptFile(current_file.name, fileData).then(acceptEncryptedData);
			});
			reader.readAsArrayBuffer(current_file);
		}

		return true;
	});
});

function getCurrentKey() {
	var recipient = document.getElementById("recipientSelect");
	var recipientId = recipient.value; // here we expect one of 4: legal, devcon, esp, security
	var publicKeyArmored = publicKeys[recipientId];
	return publicKeyArmored;
}

async function encrypt(msg) {
	const publicKey = await openpgp.readKey({ armoredKey: getCurrentKey() });
	const encrypted = await openpgp.encrypt({
		message: await openpgp.createMessage({ text: msg }),
		encryptionKeys: publicKey
	});

	encryptedFixed = encrypted.replace(/\n/g, "<br />");
	return { name: 'message', data: encryptedFixed };
}

async function encryptFile(filename, file) {
	const publicKey = await openpgp.readKey({ armoredKey: getCurrentKey() });
	const encrypted = await openpgp.encrypt({
		message: await openpgp.createMessage({ binary: file }),
		encryptionKeys: publicKey,
		format: 'armored'
	});

	return { name: filename, data: encrypted };
}

// Turnstile callback functions
function captchaSolved(turnstileResponse) {
	document.getElementById("button").disabled = false;
}

function captchaExpired() {
	document.getElementById("button").disabled = true;
}

async function postData(url = '/', data = {}) {
	const response = await fetch(url, {
	  method: 'POST',
	  headers: {
		'Content-Type': 'application/json'
	  },
	  body: JSON.stringify(data)
	});
	return response.json();
}
  
function displayResult(status, message) {
	const formElement = document.getElementById("submission-form");
	const statusText = (status == "success") ? "Success!" : "Error";
	
	// If success message, format the identifier specially
	if (status === "success" && message.includes("Please record the identifier")) {
		// Extract the identifier (format: recipient:YYYY:MM:DD:HH:MM:SS:XXXX)
		const identifierMatch = message.match(/([a-zA-Z]+:\d{4}:\d{2}:\d{2}:\d{2}:\d{2}:\d{2}:\d{4})$/);
		if (identifierMatch) {
			const identifier = identifierMatch[1];
			const messageWithoutId = message.substring(0, message.lastIndexOf(identifier)).trim();
			message = `${messageWithoutId} <span class="legal-identifier">${identifier}</span>`;
		}
	}
	
	formElement.innerHTML = `<fieldset><legend>${statusText}</legend><span class='pure-form-message ${status === "success" ? "success-message" : ""}'>${message}</span><br><br><span class='pure-form-message'><a href="#" onclick="location.reload()">Send one more submission</a></span></fieldset>`
}
