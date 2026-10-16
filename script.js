// ==========================================
// SUSPICIOUS LOGIN & ACTIVITY DETECTOR
// Deep Evidence / Investigation Panel
// ==========================================

const securityEvidence = {

    // ==========================================
    // SUSPICIOUS IP
    // ==========================================

    ip: {
        title: "Suspicious IP Address",
        count: 12,
        risk: "HIGH",
        color: "#dc2626",

        summary:
            "12 suspicious users were detected from unfamiliar or abnormal IP addresses.",

        evidence: [
            {
                user: "alice",
                timestamp: "2026-10-16 02:10:44",
                ip: "172.16.5.22",
                location: "Mumbai",
                host: "server01",
                event: "Login attempt",
                status: "Failed"
            },

            {
                user: "alice",
                timestamp: "2026-10-16 02:11:03",
                ip: "172.16.5.22",
                location: "Mumbai",
                host: "server01",
                event: "Login attempt",
                status: "Failed"
            },

            {
                user: "alice",
                timestamp: "2026-10-16 02:11:30",
                ip: "172.16.5.22",
                location: "Mumbai",
                host: "server01",
                event: "Login attempt",
                status: "Success"
            }
        ],

        reasons: [
            "IP address is unfamiliar for this user.",
            "Login occurred at an unusual time.",
            "Multiple failed attempts occurred before success.",
            "The source location differs from the user's normal activity."
        ]
    },


    // ==========================================
    // WRONG PASSWORD
    // ==========================================

    password: {
        title: "Wrong Password Attempts",
        count: 25,
        risk: "HIGH",
        color: "#ea580c",

        summary:
            "Multiple failed authentication attempts indicate possible brute-force or password-guessing activity.",

        evidence: [
            {
                user: "bob",
                timestamp: "2026-10-15 09:20:11",
                ip: "10.10.10.5",
                location: "Hyderabad",
                host: "server02",
                event: "Login attempt",
                status: "Failed"
            },

            {
                user: "bob",
                timestamp: "2026-10-15 09:20:35",
                ip: "10.10.10.5",
                location: "Hyderabad",
                host: "server02",
                event: "Login attempt",
                status: "Failed"
            },

            {
                user: "bob",
                timestamp: "2026-10-15 09:21:02",
                ip: "10.10.10.5",
                location: "Hyderabad",
                host: "server02",
                event: "Login attempt",
                status: "Failed"
            },

            {
                user: "bob",
                timestamp: "2026-10-15 09:22:18",
                ip: "10.10.10.5",
                location: "Hyderabad",
                host: "server02",
                event: "Login attempt",
                status: "Success"
            }
        ],

        reasons: [
            "Repeated authentication failures detected.",
            "Failures occurred within a short time window.",
            "A successful login followed the failed attempts.",
            "Pattern may indicate password guessing."
        ]
    },


    // ==========================================
    // USB ACTIVITY
    // ==========================================

    usb: {
        title: "USB Drive Activity",
        count: 13,
        risk: "MEDIUM",
        color: "#ca8a04",

        summary:
            "USB activity was detected and requires investigation.",

        evidence: [
            {
                user: "employee01",
                timestamp: "2026-10-15 14:32:11",
                device: "USB Storage",
                host: "workstation07",
                action: "USB connected",
                status: "Detected"
            },

            {
                user: "employee01",
                timestamp: "2026-10-15 14:35:42",
                device: "USB Storage",
                host: "workstation07",
                action: "File copied",
                status: "Detected"
            }
        ],

        reasons: [
            "External storage device detected.",
            "File transfer activity was observed.",
            "USB activity occurred on a monitored workstation."
        ]
    },


    // ==========================================
    // SUSPICIOUS LINKS
    // ==========================================

    links: {
        title: "Suspicious Links",
        count: 15,
        risk: "HIGH",
        color: "#dc2626",

        summary:
            "Potentially suspicious URLs were detected in security activity.",

        evidence: [
            {
                user: "employee02",
                timestamp: "2026-10-15 11:21:42",
                url: "http://example-login-security.com",
                source: "Email",
                action: "URL clicked",
                status: "Suspicious"
            },

            {
                user: "employee02",
                timestamp: "2026-10-15 11:22:08",
                url: "http://account-verification-example.com",
                source: "Email",
                action: "URL opened",
                status: "Suspicious"
            }
        ],

        reasons: [
            "URL does not match a known trusted domain.",
            "Link contains account-verification language.",
            "Potential phishing characteristics detected."
        ]
    }

};


// ==========================================
// CREATE EVIDENCE MODAL
// ==========================================

function createEvidenceModal() {

    // Prevent duplicate modal creation
    if (document.getElementById("evidenceModal")) {
        return;
    }

    const modal = document.createElement("div");

    modal.id = "evidenceModal";

    modal.innerHTML = `
        <div class="evidence-overlay">

            <div class="evidence-box">

                <button
                    class="close-evidence"
                    onclick="closeEvidence()"
                    aria-label="Close">
                    ×
                </button>

                <div id="evidenceContent"></div>

            </div>

        </div>
    `;

    document.body.appendChild(modal);
}


// ==========================================
// SHOW EVIDENCE
// ==========================================

function showEvidence(type) {

    const data = securityEvidence[type];

    if (!data) {
        console.error("Evidence not found:", type);
        return;
    }

    const modal = document.getElementById("evidenceModal");
    const content = document.getElementById("evidenceContent");

    if (!modal || !content) {
        console.error("Evidence modal was not created.");
        return;
    }


    // ==========================================
    // CREATE EVIDENCE EVENTS
    // ==========================================

    let evidenceRows = "";

    data.evidence.forEach((item, index) => {

        evidenceRows += `
            <div class="evidence-event">

                <div class="event-number">
                    ${index + 1}
                </div>

                <div class="event-details">

                    <strong>
                        ${item.event || item.action || "Security Event"}
                    </strong>

                    <p>
                        <b>User:</b>
                        ${item.user || "Unknown"}
                    </p>

                    <p>
                        <b>Time:</b>
                        ${item.timestamp || "Unknown"}
                    </p>

                    ${
                        item.ip
                            ? `
                                <p>
                                    <b>IP Address:</b>
                                    ${item.ip}
                                </p>
                              `
                            : ""
                    }

                    ${
                        item.location
                            ? `
                                <p>
                                    <b>Location:</b>
                                    ${item.location}
                                </p>
                              `
                            : ""
                    }

                    ${
                        item.host
                            ? `
                                <p>
                                    <b>Host:</b>
                                    ${item.host}
                                </p>
                              `
                            : ""
                    }

                    ${
                        item.device
                            ? `
                                <p>
                                    <b>Device:</b>
                                    ${item.device}
                                </p>
                              `
                            : ""
                    }

                    ${
                        item.url
                            ? `
                                <p>
                                    <b>URL:</b>
                                    ${item.url}
                                </p>
                              `
                            : ""
                    }

                    ${
                        item.source
                            ? `
                                <p>
                                    <b>Source:</b>
                                    ${item.source}
                                </p>
                              `
                            : ""
                    }

                    ${
                        item.action
                            ? `
                                <p>
                                    <b>Action:</b>
                                    ${item.action}
                                </p>
                              `
                            : ""
                    }

                    <p>
                        <b>Status:</b>

                        <span class="status-badge">
                            ${item.status || "Detected"}
                        </span>
                    </p>

                </div>

            </div>
        `;
    });


    // ==========================================
    // CREATE REASONS
    // ==========================================

    let reasons = "";

    data.reasons.forEach(reason => {

        reasons += `
            <li>
                ${reason}
            </li>
        `;

    });


    // ==========================================
    // DISPLAY EVIDENCE
    // ==========================================

    content.innerHTML = `

        <div class="evidence-header">

            <div>

                <h2>
                    ${data.title}
                </h2>

                <p>
                    ${data.summary}
                </p>

            </div>


            <div class="risk-box">

                <small>
                    RISK LEVEL
                </small>

                <strong>
                    ${data.risk}
                </strong>

            </div>

        </div>


        <!-- STATISTICS -->

        <div class="evidence-stat">

            <div>

                <span>
                    Detected Events
                </span>

                <strong>
                    ${data.count}
                </strong>

            </div>


            <div>

                <span>
                    Risk Level
                </span>

                <strong>
                    ${data.risk}
                </strong>

            </div>


            <div>

                <span>
                    Evidence Records
                </span>

                <strong>
                    ${data.evidence.length}
                </strong>

            </div>

        </div>


        <!-- DETAILED EVIDENCE -->

        <h3>
            🔎 Detailed Evidence
        </h3>

        <div class="timeline">

            ${evidenceRows}

        </div>


        <!-- REASONS -->

        <h3>
            ⚠ Why Was This Flagged?
        </h3>

        <div class="reason-box">

            <ul>
                ${reasons}
            </ul>

        </div>


        <!-- RECOMMENDATION -->

        <h3>
            🛡 Recommended Investigation
        </h3>

        <div class="recommendation">

            <p>
                Review the user's recent authentication history,
                compare the activity with the user's normal behaviour,
                and verify whether the activity was authorized.
            </p>

            <button
                onclick="markAsInvestigated('${type}')">
                ✓ Mark as Investigated
            </button>

        </div>

    `;


    // ==========================================
    // SHOW MODAL
    // ==========================================

    modal.style.display = "flex";
}


// ==========================================
// CLOSE MODAL
// ==========================================

function closeEvidence() {

    const modal = document.getElementById("evidenceModal");

    if (modal) {
        modal.style.display = "none";
    }

}


// ==========================================
// MARK AS INVESTIGATED
// ==========================================

function markAsInvestigated(type) {

    const data = securityEvidence[type];

    if (!data) {
        return;
    }

    alert(
        data.title +
        " has been marked as investigated."
    );

}


// ==========================================
// CONNECT DASHBOARD CARDS
// ==========================================

document.addEventListener("DOMContentLoaded", () => {

    // Create modal
    createEvidenceModal();


    // Find dashboard cards
    const cards = document.querySelectorAll(".stat-card");


    cards.forEach(card => {

        const titleElement = card.querySelector("h3");

        const title =
            titleElement
                ? titleElement.innerText.trim()
                : card.innerText.trim();


        // Make card clickable
        card.style.cursor = "pointer";


        // ==========================================
        // SUSPICIOUS IP
        // ==========================================

        if (title.includes("Suspicious IP")) {

            card.addEventListener("click", () => {
                showEvidence("ip");
            });

        }


        // ==========================================
        // WRONG PASSWORD
        // ==========================================

        else if (title.includes("Wrong Password")) {

            card.addEventListener("click", () => {
                showEvidence("password");
            });

        }


        // ==========================================
        // USB
        // ==========================================

        else if (title.includes("USB")) {

            card.addEventListener("click", () => {
                showEvidence("usb");
            });

        }


        // ==========================================
        // SUSPICIOUS LINKS
        // ==========================================

        else if (title.includes("Suspicious Links")) {

            card.addEventListener("click", () => {
                showEvidence("links");
            });

        }

    });

});