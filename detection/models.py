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

        
class URLScan(models.Model):
    STATUS_CHOICES=(
        ('Safe','Safe'),
        ('Phishing','Phishing'))
    

    url=models.URLField(max_length=500)
    status=models.CharField(max_length=10,choices=STATUS_CHOICES)
    scan_days=models.DateTimeField(auto_now_add=True)
    threat_scores=models.IntegerField(default=0)


    
    
    def save(self,*args, **kwargs):
        if self.status=="Phishing":
            self.threat_scores=50
        else:
            self.threat_scores=10
        super().save(*args, **kwargs)
    def __str__(self):
        return f"{self.url} - {self.status}"
    

class UploadFile(models.Model):
    file=models.FileField(upload_to="uploads/")
    upload_at=models.DateTimeField(auto_now_add=True)

    def str(self):
        return f"{self.file} - {self.upload_at}"