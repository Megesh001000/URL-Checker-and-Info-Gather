from django.shortcuts import render, get_object_or_404,redirect
from django.http import HttpResponse
import re

from .models import URLHistory

from detection.models import URLHistory
from django.core.paginator import Paginator
from django.urls import reverse

def home(request):
    return render(request,"detection/home.html")





# views.py or utils.py

# def check_url_safety(url):
   
#     safe_domains = ["google.com", "chatgpt.com", "openai.com"]
    
#     for domain in safe_domains:
#         if domain in url:
#             return "Safe"
    
#     suspicious_keywords = ["login", "verify", "bank", "account"]
#     for word in suspicious_keywords:
#         if word in url:
#             return "Suspicious"
    
#     return "Phishing"

import re
from django.shortcuts import render
from .models import URLHistory

def result(request):
    url = request.GET.get("url", "").strip()
    score = 0

    phishing_keywords = ["phish", "malware", "fake", "clickhere", "verify", "update", "login", "account", "secure"]
    suspicious_patterns = [r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"@", r"http://"]

    # Scoring logic
    for keyword in phishing_keywords:
        if keyword in url.lower():
            score += 5
    for pattern in suspicious_patterns:
        if re.search(pattern, url.lower()):
            score += 5
    if url.lower().startswith("https://"):
        score -= 2

    # Determine result
    if score <= 0:
        result_text = "Safe"
        css_class = "text-success"
        tip = "This website looks trustworthy."
    elif score <= 5:
        result_text = "Suspicious"
        css_class = "text-warning"
        tip = "Some indicators suggest caution."
    else:
        result_text = "Phishing"
        css_class = "text-danger"
        tip = "Avoid entering credentials or personal data."

    # Save to history
    if url:
        URLHistory.objects.create(url=url, result=result_text)

    # Pass context to template
    context = {
        "url": url,
        "result": result_text,
        "css_class": css_class,
        "tip": tip,
    }
    return render(request, "detection/result.html", context)






def history(request):
    history_list = URLHistory.objects.all().order_by('-timestamp')  # latest first
    context = {"history": history_list}
    all_entries = URLHistory.objects.all().order_by('-timestamp')  # newest first
    paginator = Paginator(all_entries, 10)  # Show 10 entries per page

    page_number = request.GET.get('page')  # get page number from URL
    page_obj = paginator.get_page(page_number)  # get current page



    return render(request, "detection/history.html",{'history': page_obj})







def recheck(request, pk):
    entry = get_object_or_404(URLHistory, id=pk)
    # Redirect to result page with the same URL
    return redirect(f"{reverse('result')}?url={entry.url}")


def delete_entry(request, pk):
    entry = get_object_or_404(URLHistory, id=pk)
    entry.delete()
    return redirect('history')




def dashboard(request):
    return render(request,'detection/dashboard.html')