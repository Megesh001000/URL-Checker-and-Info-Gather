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
    timestamp = models.DateTimeField(auto_now_add=True)

    
    
    def save(self,*args, **kwargs):
        super().save(*args, **kwargs)
    def __str__(self):
        return f"{self.url} - {self.status}"
    

class UploadFile(models.Model):
    file_name = models.CharField(max_length=255,default="")
    file_hash = models.CharField(max_length=255,default="")
    file_size = models.IntegerField(default=0)
    mime_type = models.CharField(max_length=100,default="")
    extracted_urls = models.JSONField(default=list)
    results = models.JSONField(default=dict)
    is_phishing = models.BooleanField(default=False)
    scanned_at = models.DateTimeField(auto_now_add=True,null=True)
    
    def __str__(self):
        return f"{self.file_name} - {self.scanned_at}"

class DatasetUpload(models.Model):
    filename=models.CharField(max_length=255)
    row=models.IntegerField(default=0)
    uploaded_at=models.DateTimeField(auto_now_add=True)
    suspicious=models.BooleanField(default=False)
    message=models.TextField(blank=True,null=True)

   
    def __str__(self):
        return f"{self.filename}  ({self.row} row)"
    

class ProcessedEmail(models.Model):
    email_id=models.CharField(max_length=255,unique=True)
    subject=models.TextField(null=True,blank=True)
    sender=models.TextField(null=True,blank=True)
    processed_at=models.DateTimeField(auto_now_add=True)
    # blacklist_source=models.CharField(max_length=256,unique=True)
    # blacklist_flag=models.CharField(max_length=256,unique=True)
    blacklist_source = models.CharField(max_length=255, blank=True, null=True)
    blacklist_flag = models.BooleanField(default=False)
    threat_score = models.FloatField(default=0.0)
    has_urls = models.BooleanField(default=False)
    is_phishing = models.BooleanField(default=False)
    urls_data = models.JSONField(default=list)


    def __str__(self):
        return f"{self.subject} from {self.sender}"


class UnifiedScan(models.Model):
    MODULE_CHOICES=[
        ("URL","Manual URL Scanner"),
        ("EMAIL","Email Scanner"),
        ("ATTACHMENT","Attachment Scanner"),
        ]
    
    module=models.CharField(max_length=20,choices=MODULE_CHOICES)
    item=models.CharField(max_length=500) # url,filename,eemaail sub
    status=models.CharField( max_length=20) # safe or malicious
    detail_id=models.CharField(max_length=255,blank=True,null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    scanned_url=models.CharField(max_length=500)

    def __str__(self):
        return f"{self.module}: {self.item} → {self.status}"


    

