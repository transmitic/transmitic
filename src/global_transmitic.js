const GREEN = "#41E296";
const RED = "#E24141";

const SUCCESS = GREEN;
const ERROR = RED;

function setMsgBoxSuccess(msg) {
    setMsgBox(msg, SUCCESS);
}

function setMsgBoxError(msg) {
    setMsgBox(msg, ERROR);
}

function setMsgBox(msg, color) {
    document.$("div#msg-box").innerHTML = `
    <div style="display: inline-block; margin-right: auto;">${escapeHTML(msg)}</div>
    <img id="msg-box-close" src="ic_fluent_dismiss_square_24_filled.svg"
        style="margin-left: auto; display: inline-block; vertical-align:middle; padding-right: 40dip;" />
`
    document.$("div#msg-box").style.display = "block";
    document.$("div#msg-box").style["background-color"] = color;

    document.$("img#msg-box-close").onclick = function () {
        document.$("div#msg-box").style.display = "none";
    }
}

function escapeHTML(html) {
    let newHtml = `${html}`;
    newHtml.replaceAll('&', '&amp;').replaceAll('>', '&gt;').replaceAll('<', '&lt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
    return newHtml;
}

function eachPageReady() {
    let msgBox = document.$("#msg-box");
    let stickyPos = msgBox.state.box("top", "border", "parent");
    document.body.onscroll = function () {
        msgBox.classList.toggle("sticky", this.scrollTop > stickyPos);
    }
}

function displayWarningModal(parent) {
    var isYesModal = Window.this.modal {
        url: __DIR__ + "dialog.htm",
            parameters: { },
    parent: parent,
        alignment: -5,
            width: 400 * devicePixelRatio,
                height: 150 * devicePixelRatio,
};
var isYes = false;
if (isYesModal != null) {
    isYes = isYesModal.yes;
}

return isYes;
}

function displayHelpModal(parent, text) {
    var isYesModal = Window.this.modal {
        url: __DIR__ + "dialog_help.htm",
            parameters: { text: text },
    parent: parent,
        alignment: -5,
            width: 600 * devicePixelRatio,
                height: 300 * devicePixelRatio,
};
}