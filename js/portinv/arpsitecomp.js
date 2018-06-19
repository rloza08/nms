
function main() {
    var site = $('#site').val();

    if (isNaN(site)) {
        alert("Only numeric's are allowed in store field!");
        return false;
    }

    if (site == ' ' || site == '') {
        alert("Please enter store number");
        return false;
    }

    $("#pageloader").fadeIn();
    $("#arpsite").submit();
}

