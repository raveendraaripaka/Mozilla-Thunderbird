window.addEventListener("load", function(e) {
    context_menu_view.onLoad(e);
}, false);

var context_menu_view  = {
    initialized : false,
    onLoad: function() {
        if (this.initialized) return;
        this.initialized = true;
        
        //        var editor = document.getElementById("myEditor").contentDocument.body;
        //        editor.innerHTML = window.arguments[0].decryptText;
        //        editor.contentDocument.designMode = 'on';

        document.getElementById("myEditor")= window.arguments[0].decryptText;

        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.mystrings = this.gfiltersimportexportBundle.createBundle("chrome://Cryption_Symmetric/locale/overlay.properties");
    },

    getString:function(key) {
        try{
            var str = this.stringbundle.GetStringFromName(key);
            return str;
        }catch(e){
            return key;
        }
    }
};