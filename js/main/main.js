
function screenResolution() {
    var width = window.innerWidth + "px";

    var mainPageWidth = 81 + "%";
    var leftPageWidth = 7 + "%";

    // $("#leftnav").css("width", leftPageWidth);
    $("#main_page").css("width", mainPageWidth);
    $("#container").css("width", width);
    // cornerDivPosition();
}

function mainPageAjax(value) {
    ajaxCall(value); 
}

function ajaxCall(value) {
    $.ajax({
        method: "POST",
        url: "index.py",
        data: {menuContents: value}
    }).done (function(html){
        $('#main_page').html(html);
    });
}

function cornerDivPosition() {
    var mainPagePos = $('div').eq(8).position().value;
    // var position = mainPagePos.position();
    // alert(mainPagePos);
}

function display(x, w, h) {
     // x - URL
     // y - Target Window
     // w - window width
     // h - window height

     h = undefined;
     // set default WxH if both width and height are not passed
     if ( typeof(h) == "undefined") {
        var w = 875;
        var h = 600;
     }

     // build parameter string
     var parm = "alwaysraised=yes,locationbar=no,toolbar=no,menubar=no,personalbar=no,scrollbars=yes," +
                "resizable=yes,status=yes,width=" + w + ",height=" + h;

     winRef = window.open(x,"_blank", parm);
     winRef.focus();
}

