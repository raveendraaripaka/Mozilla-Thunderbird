
window.addEventListener("load", function(e) {
    Cryption_Symmetric_Options.onLoad(e);
}, false);

var prng;
var Cryption_Symmetric_Options  = {

    initialized : false,
    include : function(src) {
        var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].getService(Components.interfaces.mozIJSSubScriptLoader);
        loader.loadSubScript("chrome://Cryption_Symmetric/content/javascrypt/"+src);
    },

    onLoad: function() {
        if (this.initialized) return;
        this.initialized = true;
        Cryption_Symmetric_Options.init();
        
        if(window.arguments[0].condition == "0"){
            document.getElementById("Encrypt").value = window.arguments[0].encryptSelection;
            document.getElementById("Decrypt").value = window.arguments[0].encryptText;
            document.getElementById("some-password").value = window.arguments[0].Password;
        }
        else{
            document.getElementById("Encrypt").value = window.arguments[0].decryptText;
            document.getElementById("Decrypt").value = window.arguments[0].decryptSelection;
            document.getElementById("some-password").value = window.arguments[0].Password;
        }

        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.stringbundle = this.gfiltersimportexportBundle.createBundle("chrome://Cryption_Symmetric/locale/overlay.properties");

    },

    getString:function(key) {
        try{
            var str = this.stringbundle.GetStringFromName(key);
            return str;
        }
        catch(e){
            return key;
        }
    },

    encrypt : function() {

        var selection = document.getElementById("Encrypt").value;
        var pass = document.getElementById("some-password").value;
        var hint = document.getElementById("hint-password").value;

        if(pass == ""){
            alert("Enter the Password")
        }else{

            try {
                if(hint=="")
                {
                    hint="not provided"
                    var encrypted = Cryption_Symmetric_Options.encryptText(selection.toString(), pass, hint);

                    var Decryption_textbox = document.getElementById("Decrypt")
                    Decryption_textbox.value = '';

                    var Decrypted_text = document.getElementById("Decrypt");
                    Decrypted_text.value = Decrypted_text.value + encrypted;
                }
                else{
                    var encrypted_with_hint = Cryption_Symmetric_Options.encryptText(selection.toString(), pass, hint);

                    var Decryption_textbox_hint = document.getElementById("Decrypt")
                    Decryption_textbox_hint.value = '';

                    var Decrypted_text_hint = document.getElementById("Decrypt");
                    Decrypted_text_hint.value = Decrypted_text_hint.value + encrypted_with_hint;
                }
            } catch(E) {
                Components.utils.reportError(E);
                alert("Encryption failed:"+E);
            }
        }
    },

    decrypt : function() {
        var selection = document.getElementById("Decrypt").value;
        var pass = document.getElementById("some-password").value;

        try {
            if(pass == ''){
                alert("enter the passsword");
            }
            else{
                var decrypted = false;
                try {
                    decrypted = Cryption_Symmetric_Options.decryptText(selection.toString(), pass);
                } catch(E) {
                    decrypted = Cryption_Symmetric_Options.seekText(selection.toString());
                    decrypted = Cryption_Symmetric_Options.decryptText(decrypted, pass);
                }

                var encryption_textbox = document.getElementById("Encrypt")
                encryption_textbox.value = '';

                var encrypted_text = document.getElementById("Encrypt");
                encrypted_text.value = encrypted_text.value + decrypted;

            }
        } catch(E) {
            alert("Decryption failed. Propably the password is wrong, or the text is not encrypted");
        }

    },

    /* Dependent Functions and dependencies provided in the above java script */
    init : function() {
        this.include("aes.js");
        this.include("aesprng.js");
        this.include("armour.js");
        this.include("entropy.js");
        this.include("lecuyer.js");
        this.include("md5.js");
        this.include("stegodict.js");
        this.include("utf-8.js");
        ce();

    },
    addEntropy : function(doc) {
        mouseMotionEntropy(60, doc);
    },

    loadTime : (new Date()).getTime(),  // Save time page was loaded
    key : null,	     // Key (byte array)

    //	setKey  --  Set key from string or hexadecimal specification
    setKey : function(newKey) {
        var s = encode_utf8(newKey);
        var i, kmd5e, kmd5o;

        if (s.length == 1) {
            s += s;
        }

        md5_init();
        for (i = 0; i < s.length; i += 2) {
            md5_update(s.charCodeAt(i));
        }
        md5_finish();
        kmd5e = byteArrayToHex(digestBits);

        md5_init();
        for (i = 1; i < s.length; i += 2) {
            md5_update(s.charCodeAt(i));
        }
        md5_finish();
        kmd5o = byteArrayToHex(digestBits);

        var hs = kmd5e + kmd5o;
        this.key =  hexToByteArray(hs);
        hs = byteArrayToHex(this.key);
    },

    encryptText : function(plain, key, hint) {
        var v, i;
        var prefix = "-- Encrypted: decrypt with Thunderbird Cryption_symmetric Plugin\n -- Base64 Encrypted\n\n",
        suffix = "\n--  End encrypted message\n\n" + "--  This is ur password hint, in case -- " + hint;

        this.setKey(key);

        addEntropyTime();
        prng = new AESprng(keyFromEntropy());
        var plaintext = encode_utf8(plain);

        //  Compute MD5 sum of message text and add to header

        md5_init();
        for (i = 0; i < plaintext.length; i++) {
            md5_update(plaintext.charCodeAt(i));
        }
        md5_finish();
        var header = "";
        for (i = 0; i < digestBits.length; i++) {
            header += String.fromCharCode(digestBits[i]);
        }

        //  Add message length in bytes to header

        i = plaintext.length;
        header += String.fromCharCode(i >>> 24);
        header += String.fromCharCode(i >>> 16);
        header += String.fromCharCode(i >>> 8);
        header += String.fromCharCode(i & 0xFF);

        /*  The format of the actual message passed to rijndaelEncrypt
	    is:

	    	    Bytes   	Content
		     0-15   	MD5 signature of plaintext
		    16-19   	Length of plaintext, big-endian order
		    20-end  	Plaintext

	    Note that this message will be padded with zero bytes
	    to an integral number of AES blocks (blockSizeInBits / 8).
	    This does not include the initial vector for CBC
	    encryption, which is added internally by rijndaelEncrypt.

         */

        var ct = rijndaelEncrypt(header + plaintext, this.key, "CBC");
        v = armour_base64(ct);
        var result = prefix + v + suffix;
        delete prng;
        return result;
    },

    decryptText : function(cipher, plainkey) {
        this.setKey(plainkey);
        var ct = new Array(), kt;
        ct = disarm_base64(cipher);
        var result = rijndaelDecrypt(ct, this.key, "CBC");

        var header = result.slice(0, 20);
        result = result.slice(20);

        /*  Extract the length of the plaintext transmitted and
	    verify its consistency with the length decoded.  Note
	    that in many cases the decrypted messages will include
	    pad bytes added to expand the plaintext to an integral
	    number of AES blocks (blockSizeInBits / 8).  */

        var dl = (header[16] << 24) | (header[17] << 16) | (header[18] << 8) | header[19];
        if ((dl < 0) || (dl > result.length)) {
            throw "Message (length " + result.length + ") truncated.  " +
                dl + " characters expected.";
            //	Try to sauve qui peut by setting length to entire message
            dl = result.length;
        }

        /*  Compute MD5 signature of message body and verify
	    against signature in message.  While we're at it,
	    we assemble the plaintext result string.  Note that
	    the length is that just extracted above from the
	    message, *not* the full decrypted message text.
	    AES requires all messages to be an integral number
	    of blocks, and the message may have been padded with
	    zero bytes to fill out the last block; using the
	    length from the message header elides them from
	    both the MD5 computation and plaintext result.  */

        var i, plaintext = "";

        md5_init();
        for (i = 0; i < dl; i++) {
            plaintext += String.fromCharCode(result[i]);
            md5_update(result[i]);
        }
        md5_finish();

        for (i = 0; i < digestBits.length; i++) {
            if (digestBits[i] != header[i]) {
                throw "Message corrupted.  Checksum of decrypted message does not match.";
                break;
            }
        }

        //  That's it; plug plaintext into the result field

        return decode_utf8(plaintext);
    },

  
    //	Retrieve word given index in list of words of that length
    retrieveWord : function(length, index) {
        if ((length >= minw) && (length <= maxw) &&
            (index >= 0) && (index < nwords[length])) {
            return cwords[length].substring(length * index, length * (index + 1));
        }
        return "";
    },

    //	Obtain word by index in complete dictionary
    indexWord : function(index) {
        if ((index >= 0) && (index < twords)) {
            var j;

            for (j = minw; j <= maxw; j++) {
                if (index < nwords[j]) {
                    break;
                }
                index -= nwords[j];
            }
            return this.retrieveWord(j, index);
        }
        return "";
    },  

    //	Decode text from words
    seekText : function(stegotext) {

        var ct = new Array(), padded = false;

        /*  Precompute table of cumulative words before those
	    of a given length.  */
        var awords = new Array(), i, j;
        j = 0;
        for (i = minw; i <= maxw; i++) {
            awords[i] = j;
            j += nwords[i];
        }

        var t = stegotext, n = 0, v;
        var wpat = /\W*(\w+)\w*/i;
        while (wpat.test(t)) {
            //	Extract next word from text and determine its length
            t = t.replace(wpat, "");
            var w = RegExp.$1;
            var l = w.length;

            //	Look it up in the list of words of this length

            w = w.substring(0, 1).toUpperCase() +
                w.substring(1, w.length);
            v = cwords[l].indexOf(w);
            if (v >= 0) {
                v = (v / l) + awords[l];
            }
            if (v == -1) {
                throw "Bogus word "+w;
            } else {
                ct[n++] = (v >> 8) & 0xFF;
                ct[n++] = v & 0xFF;
            }
        }

        if (t.indexOf("!") != -1) {
            padded = true;
            ct.pop();
            n -= 1;
        }
        v = armour_base64(ct);
        return v;
    }
};