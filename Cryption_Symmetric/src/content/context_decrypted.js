window.addEventListener("load", function(e) {
    Cryption_Symmetric_context.onLoad(e);
}, false);

var Cryption_Symmetric_context  = {

    onLoad: function() {
        if (this.initialized) return;
        this.initialized = true;
        
        var editor = document.getElementById("Decrypted_text").contentDocument.body;
        editor.innerHTML = window.arguments[0].decryptText;
        document.getElementById("password").value = window.arguments[0].Password;

        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.stringbundle = this.gfiltersimportexportBundle.createBundle("chrome://{appname}/locale/overlay.properties");
    },

    getString:function(key) {
        try{
            var str = this.stringbundle.GetStringFromName(key);
            return str;
        }
        catch(e){
            return key;
        }
    }
};