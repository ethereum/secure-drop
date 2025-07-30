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
	maxFilesize: 15, // Max file size per file in MB
	maxFiles: 10, // Max number of files
	url: '/fake',
	paramName: 'attachment',
	autoProcessQueue: false,
	autoQueue: false,
	addRemoveLinks: true,
	uploadMultiple: true,
	dictDefaultMessage: 'Drag & drop your files here - or click to browse. You can attach multiple files, up to a total of 15 MB.',
	dictFileTooBig: 'File is too big ({{filesize}}MB). Max filesize: {{maxFilesize}}MB.',
	dictMaxFilesExceeded: 'You can only upload a maximum of {{maxFiles}} files.',
	init: function() {
		var dropzone = this;
		
		this.on("addedfile", function(file) {
			hideError(); // Clear any existing errors
			
			// Check individual file size
			if (file.size > 15 * 1024 * 1024) {
				this.removeFile(file);
				showError(`Error: File "${file.name}" is too large (${(file.size / 1024 / 1024).toFixed(2)}MB). Maximum file size is 15MB.`);
				return;
			}
			
			// Calculate the total added file size
			var totalSize = this.files.reduce(function(total, f) {
				return total + f.size;
			}, 0);
			
			// If the total added file size is greater than 15 MB, remove the file
			if (totalSize > 15 * 1024 * 1024) {
				this.removeFile(file);
				showError(`Error: Total file size would exceed the 15MB limit. Current total: ${(totalSize / 1024 / 1024).toFixed(2)}MB`);
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

		postData('/submit-encrypted-data', dataArray)
		.then(response => {
			console.log(response);
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
	});
	
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
		
		if (totalSize > 15 * 1024 * 1024) {
			showError(`Error: Total file size exceeds the 15MB limit. Current total: ${(totalSize / 1024 / 1024).toFixed(2)}MB`);
			return false;
		}
		
		// Check individual file sizes
		for (let i = 0; i < selectedFiles.length; i++) {
			if (selectedFiles[i].size > 15 * 1024 * 1024) {
				showError(`Error: File "${selectedFiles[i].name}" is too large (${(selectedFiles[i].size / 1024 / 1024).toFixed(2)}MB). Maximum file size is 15MB.`);
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
