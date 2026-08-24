// Scan Emails Function

document.getElementById('scanBtn').addEventListener('click', scanEmails);

function scanEmails() {
    const btn = document.getElementById("scanBtn");
    btn.disabled = true;
    btn.innerText = "Scanning...";

    fetch("/scan-email-json/", {
        method: "GET"
    })
    .then(res => res.json())
    .then(data => {
        btn.disabled = false;
        btn.innerText = "Scan Emails";

        if (!data.ok) {
            alert("Error scanning emails: " + data.error);
            return;
        }

        renderEmails(data.emails);
    })
    .catch(err => {
        btn.disabled = false;
        btn.innerText = "Scan Emails";
        alert("Request failed: " + err);
    });
}



// Render Table

function renderEmails(emails) {
    const tbody = document.getElementById("emailRows");
    tbody.innerHTML = "";  
     let rows=""
    emails.forEach((email, index) => {

        const isPhish = email.is_phishing;
       
       
        const row = `
       
        <tr>
            <td>${sanitizeHTML(email.subject)}</td>
            <td>${sanitizeHTML(email.from)}</td>
            <td>${renderUrls(email.urls, index)}</td>
            <td>
                ${isPhish 
                    ? '<span class="badge-danger">Phishing</span>' 
                    : '<span class="badge-safe">Safe</span>'}
            </td>
        </tr>
        
    
        `;
         rows+=row;
            

        

      
    }
);
tbody.innerHTML = rows;
}

//sanitize
function sanitizeHTML(str) {
    const div=document.createElement('div');
    div.textContent=str || "";
    return div.innerHTML
}


// URL Renderer with "Show More"

function renderUrls(urls, emailIndex) {

    if (!urls || urls.length === 0) {
        return "<i>No URLs found</i>";
    }

    let html = "";

    urls.forEach((u, i) => {

        const uid = `details-${emailIndex}-${i}`;

        const geo = u.ip_geolocation || {};

        const blacklist = u.blacklist || {};
        
        document.createElement('div');
        html += `
            <div style="margin-bottom:10px;">
                <b>${u.url}</b>
                <br>

                ${u.is_malicious
                    ? '<span class="badge-danger">⚠ Malicious</span>'
                    : '<span class="badge-safe">Safe</span>'}

                <button class="btn-show" onclick="toggleDetails('${uid}')">
                    Show More
                </button>

                <div id="${uid}" class="details-box">
                    <strong>URL:</strong> ${sanitizeHTML(u.url)} <br>
                    <strong>IP Address:</strong> ${sanitizeHTML(u.ip_address)} <br>
                    <strong>Country:</strong> ${sanitizeHTML(geo.country)} <br>
                    <strong>Region:</strong> ${sanitizeHTML(geo.region)} <br>
                    <strong>City:</strong> ${sanitizeHTML(geo.city)} <br>
                    <strong>Latitude:</strong> ${sanitizeHTML(geo.latitude)} <br>
                    <strong>Longitude:</strong> ${sanitizeHTML(geo.longitude)} <br>
                    <hr>

                    <strong>Domain Age:</strong> ${sanitizeHTML(u.domain_age)} days<br>
                    <strong>Domain Expiry:</strong> ${sanitizeHTML(u.domain_expiry)}<br>
                    <strong>DNS Record:</strong> ${sanitizeHTML(u.dns_record)}<br>
                    <hr>

                    <strong>SSL Issuer:</strong> ${sanitizeHTML(u.ssl_issuer)}<br>
                    <strong>SSL Valid:</strong> ${sanitizeHTML(u.ssl_valid)}<br>
                    <strong>SSL Expiry:</strong> ${sanitizeHTML(u.ssl_expiry)}<br>
                    <hr>

                    <strong>HTML Features:</strong><br>
                    Forms: ${sanitizeHTML(u.forms)} <br>
                    Iframes: ${sanitizeHTML(u.iframes)} <br>
                    JS Includes: ${sanitizeHTML(u.js_includes)} <br>
                    Redirect Ratio: ${sanitizeHTML(u.redirect_ratio)} <br>
                    <hr>
                    
                    <strong>Blacklist:</strong><br>
                    Blacklisted: ${sanitizeHTML(u.blacklist.blacklisted == 1  ? "YES" : "NO")} <br>
                    Source: ${sanitizeHTML(u.blacklist.source ||"N/A")} <br>
                    Details: ${sanitizeHTML(u.blacklist.details ||"N/A")} <br>
                    <hr>

                    <strong>ML Score:</strong> ${u.ml_score}<br>
                    <strong>Final Decision:</strong> ${
                        u.is_malicious
                        ? "<span style='color:red;'>Malicious</span>"
                        : "<span style='color:green;'>Safe</span>"
                    }
                </div>
            </div>
        `;
    });

    return html;
}



// Toggle Show/Hide Feature Box

function toggleDetails(id) {
    const box = document.getElementById(id);
    if (getComputedStyle(box).display === "none") {
        box.style.display="block";
    }else{
        box.style.display="none";
    }
}