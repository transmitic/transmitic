const GREEN = "#66ff6b";
const RED = "#ff4545";

const SUCCESS = GREEN;
const ERROR = RED;

// TODO auto scroll to success?
function setMsgBoxSuccess(msg) {
    document.$("div#msg-box").content(msg);
    document.$("div#msg-box").style.display = "block";
    document.$("div#msg-box").style["background-color"] = SUCCESS;
}

// TODO auto scroll up to error box
function setMsgBoxError(msg) {
    document.$("div#msg-box").content("Error: " + msg);
    document.$("div#msg-box").style.display = "block";
    document.$("div#msg-box").style["background-color"] = ERROR;
}