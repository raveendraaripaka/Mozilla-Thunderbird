window.addEventListener("load", function(e) {
    Cryption_Symmetric.onLoad(e);
}, false);


var Cryption_Symmetric  = {
    onLoad: function() {
        // initialization code
        this.initialized = true;
        this.gfiltersimportexportBundle = Components.classes["@mozilla.org/intl/stringbundle;1"].getService(Components.interfaces.nsIStringBundleService);
        this.mystrings = this.gfiltersimportexportBundle.createBundle("chrome://Cryption_Symmetric/locale/overlay.properties");
    },
    getString:function(key)
    {
        try{
            var str = this.mystrings.GetStringFromName(key);
            return str;
        }catch(e){
            return key;
        }
    },

    onMenuItemCommand: function() {
        //alert(this.getString("Continue_Confirm"));
        window.open("chrome://Cryption_Symmetric/content/options.xul", "", "chrome,titlebar,toolbar,centerscreen,modal");
    }
};