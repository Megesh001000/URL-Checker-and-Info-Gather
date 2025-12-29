import os
from pathlib import Path
import tempfile
import zipfile
import fitz
from typing import List,Dict
import docx
import csv
 
from url_checker.attachment_scanner.url_extractor import extract_urls_from_text


def extract_text_from_pdf(path:str)->str:
    text=""
    with fitz.open(path) as pdf:
        for page in pdf:
            text+=page.get_text()
    return text
    
def extract_text_from_docx(path:str)->str:
    doc=docx.Document(path)
    text='\n'.join([p.text for p in doc.paragraphs])
    return text

def extract_text_from_txt(path:str)->str:
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        return f.read()
    
def extract_from_text_csv(path:str)->str:
    text=""
    with open(path,'r',encoding='utf-8',errors='ignore') as f:
        reader=csv.reader(f)
        for row in reader:
            text+=" ".join(row)+'\n'
    return text

def extract_text_from_file(path:str)->str:
    ext=Path(path).suffix.lower()
    if ext == '.pdf':
        return extract_text_from_pdf(path)
    elif ext == '.docx':
        return extract_text_from_docx(path)
    elif ext == '.txt':
        return extract_text_from_txt(path)
    elif ext == '.csv':
        return extract_from_text_csv(path)
    else:
        return ""
    

def extract_text_from_zip(path:str)->str:
    text=""
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with zipfile.ZipFile(path,'r',) as z:
                for filename in z.namelist():
                    if filename.startswith('__MACOSX/'):
                        continue
                    ext=Path(filename).suffix.lower()
                    # if ext in ['.pdf','.txt','.csv','.docx']:
                    #     with z.open(filename) as f:
                    #         temp_path = f"_temp_{os.path.basename(filename)}"
                    #         with open(temp_path ,'wb') as temp_file:
                    #             temp_file.write(f.read())
                    #         text +=extract_text_from_file(temp_file)+'\n'

                    #     os.remove(temp_path)
                    try:
                            z.extract(filename, path=temp_dir)
                            temp_file_path = os.path.join(temp_dir, filename)

                            # Extract text from the extracted file
                            extracted_content = extract_text_from_file(temp_file_path)

                            # Add the extracted content to the aggregate text
                            text += f"Content from {filename}\n{extracted_content}\n"
                    except Exception as e:
                            print(f"Error processing file {filename} in zip: {e}")
                            
        except Exception as e:
            print(f"Error handling ZIP file {path}: {e}")
    
        return text
def scan_file_for_urls(path:str)-> Dict[str,List[str]]:
    ext=Path(path).suffix.lower()
    if ext == '.zip':
        text = extract_text_from_zip(path)
    else:
        text = extract_text_from_file(path)
    
    urls=extract_urls_from_text(text)
    return {"file": path, "urls": urls}

def scan_multiple_files(file_list:List[str]) -> List[Dict[str,List[str]]]:
    results=[]
    for f in file_list:
        try:
            result=scan_file_for_urls(f)
            results.append(result)
        except Exception as e:
            results.append({"file": f, "error": str(e), "urls": []})
    return results

if __name__ == "__main__":
    # Example usage
    test_files = ["url_checker/tf/example.pdf", "url_checker/tf/example.docx", "url_checker/tf/example.txt", "url_checker/tf/example.csv"]
    results = scan_multiple_files(test_files)
    for r in results:
        print(f"\nFile: {r['file']}")
        if "error" in r:
            print(f"Error: {r['error']}")
        else:
            print("URLs found:", r["urls"])
        