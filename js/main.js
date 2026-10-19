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

// ---------- Comment form → WhatsApp (Impact page only) ----------
// Comments aren't stored anywhere: the form opens WhatsApp with the comment
// already typed, addressed to our number, and the visitor taps Send.
var WHATSAPP_NUMBER = "254790454212";
var commentForm = document.getElementById("commentForm");

if (commentForm) {
    commentForm.addEventListener("submit", function (event) {
        event.preventDefault();

        // Single-line fields: collapse any line breaks/extra spaces.
        // The browser's required/maxlength/email checks have already run.
        var name = commentForm.elements.name.value.replace(/\s+/g, " ").trim();
        var email = commentForm.elements.email.value.replace(/\s+/g, "").trim();
        var comment = commentForm.elements.comment.value.trim();

        if (!name || !comment) {
            return;
        }

        var text = "Comment from the Nyandior Pads website (Impact page)\n\n" +
                   "Name: " + name + "\n" +
                   (email ? "Email: " + email + "\n" : "") +
                   "\n" + comment;

        // encodeURIComponent makes the text safe to put in the link
        window.open("https://wa.me/" + WHATSAPP_NUMBER + "?text=" + encodeURIComponent(text),
                    "_blank", "noopener,noreferrer");

        commentForm.reset();
        var commentStatus = document.getElementById("commentStatus");
        commentStatus.textContent = "WhatsApp has opened with your comment. Tap Send to share it with us. Thank you!";
        commentStatus.hidden = false;
    });
}

// ---------- Contact form result (contact page only) ----------
// The form handler redirects back with ?status=success|invalid|error.
// Only these known values are used, and the message is set with textContent,
// so nothing from the URL is ever inserted into the page as HTML.
var formStatus = document.getElementById("formStatus");

if (formStatus) {
    var formMessages = {
        success: "Thank you! Your message has been sent. We'll get back to you soon.",
        invalid: "Some details were missing or too long. Please check each field and try again.",
        error: "Sorry, your message could not be sent. Please check your email address and try again, or reach us on WhatsApp."
    };
    var formResult = new URLSearchParams(window.location.search).get("status");

    if (Object.prototype.hasOwnProperty.call(formMessages, formResult)) {
        formStatus.textContent = formMessages[formResult];
        formStatus.className = "form-status " + (formResult === "success" ? "success" : "error");
        formStatus.hidden = false;
        history.replaceState(null, "", window.location.pathname);
    }
}
