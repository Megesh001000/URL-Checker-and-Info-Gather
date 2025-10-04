from django.db import models

class URLHistory(models.Model):
    RESULT_CHOICES = [
        ("Safe", "Safe"),
        ("Suspicious", "Suspicious"),
        ("Phishing", "Phishing")
    ]

    url = models.URLField(max_length=500)
    result = models.CharField(max_length=20, choices=RESULT_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.result}"
