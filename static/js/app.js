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

	// Custom text for ESP recipient
	recipient.addEventListener("change", function() {
		messageLabel.innerHTML = (recipient.value == "esp") ? "Please include Grant ID in the message. Example: \"FY22-0123\":" : "Message:";
	});

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
		const form = evt.target;
		
		const selectedFiles = Dropzone.instances[0].files || [];
		var promises = [];

		for (var i=0; i < selectedFiles.length; i++) {
			current_file = selectedFiles[i];
			filename_field = form.elements['filename-' + i];
			attachment_field = form.elements['attachment-' + i];

			filename_field.value = current_file.name;

			var reader = new FileReader();
			// special treatment for `addEventListener` in a *for loop*
			reader.attachment_field = attachment_field;
			reader.addEventListener('load', (event) => {
				var arrayBuffer = event.target.result;
				var fileData = new Uint8Array(arrayBuffer);
				var encryptionPromise = encryptFile(fileData).then(function(encrypted_file) {
					// parameters for `addEventListener` in a *for loop* need a special treatment
					// the only working solution seems to be: https://stackoverflow.com/a/11986895
					event.target.attachment_field.value = encrypted_file;
				});
				promises.push(encryptionPromise);
			});
			reader.readAsArrayBuffer(current_file);
		}

		// Wait for all encryption promises to resolve before submitting the form
		Promise.all(promises).then(() => {
			// Defer the Promise.all() call to the next event loop iteration to ensure that the DOM is fully updated
			Promise.resolve().then(() => {
				encrypt(text.value).then(function(encrypted_msg) {
					form.elements['message'].value = encrypted_msg;
					form.elements['recipient'].value = recipient.value;
					form.submit();
				});
			});
		});

		return true;
	});
});

async function encrypt(msg) {
	var recipient = document.getElementById("recipientSelect");
	var recipientId = recipient.value; // here we expect one of 4: legal, devcon, esp, security
	var publicKeyArmored = publicKeys[recipientId];
	const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
	const encrypted = await openpgp.encrypt({
		message: await openpgp.createMessage({ text: msg }),
		encryptionKeys: publicKey
	});
	encryptedFixed = encrypted.replace(/\n/g, "<br />");
	return encryptedFixed;
}

async function encryptFile(file) {
	var recipient = document.getElementById("recipientSelect");
	var recipientId = recipient.value;
	var publicKeyArmored = publicKeys[recipientId];
	const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
	const message = await openpgp.createMessage({ binary: file });
	const encrypted = openpgp.encrypt({
		message,
		encryptionKeys: publicKey,
		format: 'armored'
	});
	return encrypted;
}

function enableBtn(){
   document.getElementById("button").disabled = false;
}
