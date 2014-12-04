window.addEventListener("load", function(e) {
    status_bar.onLoad(e);
}, false);


var prng;
var status_bar  = {
    initialized : false,

    include : function(src) {
        var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].getService(Components.interfaces.mozIJSSubScriptLoader);
        loader.loadSubScript("chrome://Cryption_Symmetric/content/javascrypt/"+src);
    },

    onLoad: function() {
        if (this.initialized) return;
        this.initialized = true;
        status_bar.init();

        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.stringbundle = this.gfiltersimportexportBundle.createBundle("chrome://Cryption_Symmetric/locale/overlay.properties");
    },

    getString:function(key) {
        try{
            var str = this.stringbundle.GetStringFromName(key);
            return str;
        }catch(e)
        {
            return key;
        }
    },

    onMenuItemCommand: function() {
        //alert(this.getString("Continue_Confirm"));
        window.open("chrome://Cryption_Symmetric/content/options.xul", "", "chrome,titlebar,toolbar,centerscreen,modal");
    },

    close: function(){
        document.getElementById("wrapper").hidden= "true";
    },

    showDecryptionBar_enable: function(){

        document.getElementById("decryptionbar").setAttribute("hidden", "false");
    },

    showDecryptionBar_disable: function(){

        document.getElementById("decryptionbar").setAttribute("hidden", "true");
    },

    decrypt_mail : function() {        
        var aMessageHeader = gFolderDisplay.selectedMessage;
        if(aMessageHeader == null)
        {
            alert("select a Message above");
        }
        else{            
            var messenger = Components.classes["@mozilla.org/messenger;1"].createInstance(Components.interfaces.nsIMessenger);
            var listener = Components.classes["@mozilla.org/network/sync-stream-listener;1"].createInstance(Components.interfaces.nsISyncStreamListener);
            var uri = aMessageHeader.folder.getUriForMsg(aMessageHeader);
            messenger.messageServiceFromURI(uri).streamMessage(uri, listener, null, null, false, "");
            var folder = aMessageHeader.folder;
            var selection =folder.getMsgTextFromStream(listener.inputStream, aMessageHeader.Charset, 65536, 32768, false, true,{ });

            
            var pass = document.getElementById("password").value;

            try {
                var decrypted = false;
                if(pass == ""){
                    alert("enter the password below");
                }
                else{
                    try {
                        decrypted = status_bar.decryptText(selection.toString(), pass);
                    } catch(E) {
                        decrypted = status_bar.seekText(selection.toString());
                        decrypted = status_bar.decryptText(decrypted, pass.value);
                    }

                    document.getElementById("wrapper").setAttribute("hidden", "false");
                    document.getElementById('desc').textContent =decrypted;
                }
            } catch(E) {
                alert("Decryption failed. Propably the password is wrong, or the text is not encrypted");
            }

        }
    },


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

    decryptText : function(cipher, plainkey) {
        this.setKey(plainkey);
        var ct = new Array(), kt;
        ct = disarm_base64(cipher);
        var result = rijndaelDecrypt(ct, this.key, "CBC");

        var header = result.slice(0, 20);
        result = result.slice(20);

        /*  Extract the length of the plaintext transmitted and verify its consistency with the length decoded.  Note
	    that in many cases the decrypted messages will include pad bytes added to expand the plaintext to an integral
	    number of AES blocks (blockSizeInBits / 8).  */

        var dl = (header[16] << 24) | (header[17] << 16) | (header[18] << 8) | header[19];
        if ((dl < 0) || (dl > result.length)) {
            throw "Message (length " + result.length + ") truncated.  " +
            dl + " characters expected.";
            //	Try to sauve qui peut by setting length to entire message
            dl = result.length;
        }

        /*  Compute MD5 signature of message body and verify against signature in message.  While we're at it,
	    we assemble the plaintext result string.  Note that the length is that just extracted above from the
	    message, *not* the full decrypted message text. AES requires all messages to be an integral number
	    of blocks, and the message may have been padded with zero bytes to fill out the last block; using the
	    length from the message header elides them from both the MD5 computation and plaintext result.  */

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
        return decode_utf8(plaintext);
    },

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



