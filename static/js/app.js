document.addEventListener('DOMContentLoaded', function() {
	document.getElementById("text").focus();
	var text = document.getElementById("text");
	var recipient = document.getElementById("recipientSelect");
	var recipientLabel = document.getElementById("recipientLabel");

	// We can have recipient set in the URL
	const params = new URLSearchParams(window.location.search);
	const name = params.get("recipient");
	if(name && name != "") {
		recipient.value = name;
		recipient.style.visibility = 'hidden';
		recipientLabel.style.visibility = 'hidden';
	};

	// TODO: multi file upload
	const fileSelector = document.getElementById('file-selector');
	fileSelector.addEventListener('change', (event) => {
		const fileList = event.target.files;

		var i = 0;
		form.elements['filename-' + i].value = fileList[i].name;
		const reader = new FileReader();
		reader.addEventListener('load', (event) => {
			var arrayBuffer = event.target.result;
			var fileData = new Uint8Array(arrayBuffer);
			encryptFile(fileData).then(function(encrypted_file) {
				form.elements['attachment-' + i].value = encrypted_file;
			});
		});
		reader.readAsArrayBuffer(fileList[i]);
	}, false);

	document.forms[0].addEventListener("submit", function(evt) {
		evt.preventDefault();
		encrypt(text.value).then(function(encrypted_msg) {
			form.elements['message'].value = encrypted_msg;
			form.elements['recipient'].value = recipient.value;
			form.submit();
		});
		return true;
	});
});

async function encrypt(msg) {
	var recipient = document.getElementById("recipientSelect");
	var recipientId = recipient.value;
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
	const encrypted = await openpgp.encrypt({
		message,
		encryptionKeys: publicKey,
		format: 'armored'
	});
	return encrypted;
}

function enableBtn(){
   document.getElementById("button").disabled = false;
}
