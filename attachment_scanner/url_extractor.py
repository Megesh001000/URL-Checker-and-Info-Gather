import io
import os
import re
import fitz
import docx
import  csv
import zipfile
from typing import List

URL_PATTERN=re.compile(
    r'('
    r'(?:https?|ftp)://[^\s<>"\'(){}\[\]]+'     # scheme://...
    r'|www\.[^\s<>"\'(){}\[\]]+'                # www...
    r'|\b\d{1,3}(?:\.\d{1,3}){3}\b(?:[:]\d{1,5})?(?:/[^\s<>"\'(){}\[\]]*)?'  # IP[:port][/path]
    r')',re.IGNORECASE)



TRAILING_PUNCT = re.compile(r'[.,;:)\]}>\'"]+$')
def extract_text_from_txtFile(filepath:str)-> str:
    try:
        with open(filepath,'r',encoding='utf-8',errors='ignore') as f :
            return f.read()
    except Exception as e:
        print(f"[ERROR] Unable to read text file: {e} ")
        return ""

def extract_text_from_pdf(filepath:str)->str:
    text=""
    try:
        with  fitz.open(filepath) as pdf:
            for page in pdf:
                text+=page.get_text('text')
        return text
    except Exception as e:
        print(f"[ERROR] PDF Extraction Failed: {e} ")
        return ""
    
def extract_text_from_docx(filepath:str)->str:
    text=""
    try:
        doc=docx.Document(filepath)
        for para in doc.paragraphs:
            text+=para.text +"\n"
        return text
    except Exception as e:
        print(f"[ERROR] DOCX Extraction Failed: {e} ")
        return ""
    
def extract_urls_from_text(text:str) ->List[str]:
    matches = [m.group(0) for m in re.finditer(URL_PATTERN, text)]
    cleaned_urls = []
    seen=set()
    for url in matches:
        url = TRAILING_PUNCT.sub("", url)
        if not re.match(r'^(?:https?|ftp)://', url, re.IGNORECASE):
            url = "http://" + url
        if url not in seen:
            cleaned_urls.append(url)
            seen.add(url)
    return cleaned_urls

def extract_urls_from_csv(filepath:str)->str:
    try:
        text=""
        with open(filepath,'r',encoding='utf-8',errors='ignore') as f:
            reader=csv.reader(f)
            for row  in reader:
                text+=" ".join(row)+'\n'
        return text
    except Exception as e:
        print(f"[ERROR] CSV Extraction Failed: {e}")
        return ""

def extract_urls_from_zip(filepath:str)->List[str]:
    urls_found=[]
    try:
        with zipfile.ZipFile(filepath,'r') as z:
            for filename in z.namelist():
                ext=os.path.splitext(filename)[1].lower()
                if ext in ['.pdf','.txt','.csv','.docx']:
                    temp_path=f"_temp_{os.path.basename(filename)}"
                    with z.open(filename) as f:
                        with open(temp_path,'wb') as temp:
                            temp.write(f.read())
                    urls_found.extend(extract_urls_from_files(temp_path))
                    os.remove(temp_path)
    except Exception as e:
        print(f"[ERROR] ZIP Extraction Failed: {e}")
    return list(set(urls_found))


def extract_urls_from_files(filepath:str)->List[str]:

    if not os.path.exists(filepath):
        print(f'[ERROR] File Not Found: {filepath}')
        return []
    ext=os.path.splitext(filepath)[1].lower()
    text=""
    if ext == ".txt":
        text=extract_text_from_txtFile(filepath)
    elif ext == ".pdf":
        text=extract_text_from_pdf(filepath)
    elif ext in ('.docx','.doc'):
        text=extract_text_from_docx(filepath)
    elif ext == '.csv':
        text=extract_urls_from_csv(filepath)
    elif ext =='.zip':
        text=extract_urls_from_zip(filepath)   
    else:
        try:
            # Fallback for unknown types
            with open(filepath,'rb')as f:
                raw=f.read().decode("utf-8",errors="ignore")
                text=raw
        except Exception as e:
            print(f"[ERROR] Could not read fallback file: {e}")
            return []

    urls=extract_urls_from_text(text)
    print(f"[INFO] Found {len(urls)} URLs in file: {filepath}")
    return urls

if __name__ == "__main__":
    path = "url_checker/tf/example.txt"
    print("[DEBUG] Testing file:", path)
    text = extract_text_from_txtFile(path)
    print("[DEBUG] Text length:", len(text))
    print("[DEBUG] Preview:", repr(text[:200]))
    urls = extract_urls_from_text(text)
    print("[DEBUG] URLs found:", urls)
