document.addEventListener('DOMContentLoaded', function() {
  const checkBtn = document.getElementById('checkBtn');
  const urlInput = document.getElementById('urlInput');
  const resultBox = document.getElementById('resultBox');

  checkBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) return alert('Please enter a URL');

    resultBox.style.display = 'block';
    resultBox.className = 'result p-3 rounded shadow-lg';
    resultBox.innerHTML = 'Checking...';
    resultBox.classList.remove('bg-safe','bg-phishing','bg-suspicious','show');

    try {
      const response = await fetch('/api/check_url/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
        body: JSON.stringify({ url })
      });
      const data = await response.json();

      if (data.status === 'safe') resultBox.classList.add('bg-safe');
      else if (data.status === 'phishing') resultBox.classList.add('bg-phishing');
      else resultBox.classList.add('bg-suspicious');

      resultBox.innerHTML = `
        <i class="fas fa-shield-alt"></i> <strong>Status:</strong> ${data.status}<br>
        <strong>Threat Score:</strong> ${data.threat_score}
      `;

      // Show animation
      setTimeout(() => resultBox.classList.add('show'), 50);

    } catch (err) {
      resultBox.classList.add('bg-phishing', 'show');
      resultBox.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error checking URL';
    }
  });

  // CSRF token for Django
  function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      const cookies = document.cookie.split(';');
      for (let i=0; i<cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.substring(0, name.length+1) === (name+'=')) {
          cookieValue = decodeURIComponent(cookie.substring(name.length+1));
          break;
        }
      }
    }
    return cookieValue;
  }
});



//  Email Scan 
document.getElementById('scanBtn').addEventListener('click',() =>{
  const resultDiv=document.getElementById('emailResults');
  resultDiv.innerHTML=<p>Scanning emails... Please wait.</p>

  fetch("{% url 'scan_email_api'%}")
  .then(response=response.json())
  .then(data =>{
       resultDiv.innerHTML='';
       if(data.results.length ===0){
          resultsDiv.innerHTML = '<p>No suspicious URLs found in emails.</p>';
       } else{
            data.results.forEach(items => {
              const div=document.createElement('div');
              div.className='card p-2 mb-2';
              div.innerHTML=`
              <strong>From:</strong> ${item.from}<br>
              <strong>Subject:</strong> ${item.subject}<br>
              <strong>URL:</strong><a href="${item.url}" target="_blank">${item.url}</a><br>
              <strong>Safe:</strong>${item.safe}
              `;
              resultDiv.appendChild(div);
              })
       }
  })

  .catch(err => {
          resultsDiv.innerHTML = `<p class="text-danger">Error scanning emails: ${err}</p>`;
      });
});



