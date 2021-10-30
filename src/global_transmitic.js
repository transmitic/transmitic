const GREEN = "#66ff6b";
const RED = "#ff4545";

const SUCCESS = GREEN;
const ERROR = RED;

function setMsgBoxSuccess(msg) {
    document.$("div#msg-box").content(msg);
    document.$("div#msg-box").style.display = "block";
    document.$("div#msg-box").style["background-color"] = SUCCESS;
}

function setMsgBoxError(msg) {
    document.$("div#msg-box").content("Error: " + msg);
    document.$("div#msg-box").style.display = "block";
    document.$("div#msg-box").style["background-color"] = ERROR;
}