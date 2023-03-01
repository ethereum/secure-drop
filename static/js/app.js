Dropzone.options.dropzoneArea = {
	maxFilesize: 5, // Max file size per file
	maxFiles: 10, // Max number of files
	url: '/fake',
	paramName: 'attachment',
	autoProcessQueue: false,
	autoQueue: false,
	addRemoveLinks: true,
	uploadMultiple: true,
	dictDefaultMessage: 'You may drop files here to upload',
	init: function() {
		this.on("addedfile", function(file) {
		  // Calculate the total added file size
		  var totalSize = this.files.reduce(function(total, f) {
			return total + f.size;
		  }, 0);
		  
		  // If the total added file size is greater than 15 MB, remove the file
		  if (totalSize > 15 * 1024 * 1024) {
			this.removeFile(file);
			alert("Total file size exceeded the limit of 15 MB, file cannot be added.");
		  }
		});
		
		this.on("removedfile", function(file) {
		  // Calculate the total added file size
		  var totalSize = this.files.reduce(function(total, f) {
			return total + f.size;
		  }, 0);
		  
		  // Log the total added file size
		  console.log("Total file size: " + totalSize);
		});
	}
};

function initDropzone() {
	var myDropzone = new Dropzone(document.getElementById("dropzone-area"), {
		url: '/fake',
		paramName: 'attachment',
		autoProcessQueue: false,
		autoQueue: false,
		addRemoveLinks: true,
		uploadMultiple: true,
		dictDefaultMessage: 'You may drop files here to upload',
		maxFilesize: 15, // Max file size per file
		maxFiles: 10, // Max number of files
		init: function() {
		  this.on("addedfile", function(file) {
			// Calculate the total added file size
			var totalSize = this.files.reduce(function(total, f) {
			  return total + f.size;
			}, 0);
			
			// If the total added file size is greater than 15 MB, remove the file
			if (totalSize > 15 * 1024 * 1024) {
			  this.removeFile(file);
			  alert("Total file size exceeded the limit of 15 MB.");
			}
		  });
		  
		  this.on("removedfile", function(file) {
			// Calculate the total added file size
			var totalSize = this.files.reduce(function(total, f) {
			  return total + f.size;
			}, 0);
			
			// Log the total added file size
			console.log("Total file size: " + totalSize);
		  });
		}
	  });
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
		const gRecaptchaBlock = document.getElementById('gRecaptcha');
		const recipient = document.getElementById("recipientSelect");

		dataArray['g-recaptcha-response'] = gRecaptchaBlock ? grecaptcha.getResponse() : null;
		dataArray['recipient'] = recipient.value;

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

	// Custom text for ESP recipient only
	recipient.addEventListener("change", function() {
		messageLabel.innerHTML = (recipient.value == "esp") ? "Please include Grant ID in the message. Example: \"FY22-0123\":" : "Message:";
	});

	// Redirect clicks on a greed button
	const addFileButton = document.getElementById('add-file-button');
	addFileButton.addEventListener('click', (event) => {
		// Get a reference to the file input element used by Dropzone.js
		var fileInput = document.querySelector(".dz-hidden-input");

		// Simulate a click event on the file input element
		fileInput.click();
	});

	// Multi file upload meets encryption
	document.forms[0].addEventListener("submit", function(evt) {
		evt.preventDefault();
		captchaExpired(); // disable the submit button this way to prevent double submission
		
		const selectedFiles = Dropzone.instances[0].files || [];
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

// var gRecaptchaResponse = null;
function captchaSolved(recaptchaResponse) {
	// gRecaptchaResponse = recaptchaResponse;
	document.getElementById("button").disabled = false;
}

function captchaExpired() {
	// gRecaptchaResponse = null;
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
	formElement.innerHTML = `<fieldset><legend>${statusText}</legend><span class='pure-form-message'>${message}</span><br><br><span class='pure-form-message'><a href="#" onclick="location.reload()">Send one more submission</a></span></fieldset>`
}