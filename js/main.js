// Shared site script. Kept in its own file (not inline in the pages) so the
// Content Security Policy can forbid inline scripts, which blocks most XSS attacks.

// ---------- Mobile menu toggle ----------
var navLinks = document.getElementById("navLinks");

function showMenu() {
    navLinks.style.right = "0";
}

function hideMenu() {
    navLinks.style.right = "-200px";
}

document.querySelector("nav .fa-bars").addEventListener("click", showMenu);
document.querySelector("nav .fa-close").addEventListener("click", hideMenu);

// ---------- Forms → WhatsApp ----------
// The site has no server-side code: the contact form and the comment form
// open WhatsApp with the message already typed, addressed to our number,
// and the visitor taps Send. Nothing is stored or emailed.
var WHATSAPP_NUMBER = "254790454212";

// Collapse line breaks and extra spaces in single-line fields
function singleLine(value) {
    return value.replace(/\s+/g, " ").trim();
}

function setUpWhatsAppForm(formId, statusId, buildMessage, thankYou) {
    var form = document.getElementById(formId);
    if (!form) {
        return;
    }

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        // The browser's required/maxlength/email checks have already run
        var text = buildMessage(form.elements);
        if (!text) {
            return;
        }

        // encodeURIComponent makes the text safe to put in the link
        window.open("https://wa.me/" + WHATSAPP_NUMBER + "?text=" + encodeURIComponent(text),
                    "_blank", "noopener,noreferrer");

        form.reset();
        var status = document.getElementById(statusId);
        status.textContent = thankYou;
        status.className = "form-status success";
        status.hidden = false;
    });
}

// Contact page
setUpWhatsAppForm("contactForm", "formStatus", function (fields) {
    var name = singleLine(fields.name.value);
    var email = singleLine(fields.email.value);
    var subject = singleLine(fields.subject.value);
    var message = fields.message.value.trim();

    if (!name || !subject || !message) {
        return "";
    }
    return "Message from the Nyandior Pads website (Contact page)\n\n" +
           "Name: " + name + "\n" +
           (email ? "Email: " + email + "\n" : "") +
           "Subject: " + subject + "\n\n" +
           message;
}, "WhatsApp has opened with your message. Tap Send and we'll get back to you soon. Thank you!");

// Impact page
setUpWhatsAppForm("commentForm", "commentStatus", function (fields) {
    var name = singleLine(fields.name.value);
    var email = singleLine(fields.email.value);
    var comment = fields.comment.value.trim();

    if (!name || !comment) {
        return "";
    }
    return "Comment from the Nyandior Pads website (Impact page)\n\n" +
           "Name: " + name + "\n" +
           (email ? "Email: " + email + "\n" : "") +
           "\n" + comment;
}, "WhatsApp has opened with your comment. Tap Send to share it with us. Thank you!");
