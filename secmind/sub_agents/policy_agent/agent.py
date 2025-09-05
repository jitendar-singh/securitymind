import os
from google.adk.agents import Agent
from dotenv import load_dotenv
from PyPDF2 import PdfReader
from docx import Document
from atlassian import Confluence

load_dotenv()

# confluence = Confluence(
#     url=os.environ.get('CONFLUENCE_URL'),
#     username=os.environ.get('CONFLUENCE_USER'),
#     password=os.environ.get('CONFLUENCE_TOKEN'),
#     cloud=True
# )

def get_policies_path():
    path = os.environ.get('POLICIES_FOLDER', './policies/')
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)

def read_policy_file(policy_name: str) -> dict:
    folder_path = get_policies_path()
    file_path = os.path.join(folder_path, policy_name)
    if not os.path.exists(file_path):
        return {"status": "error", "error_message": f"File '{policy_name}' not found."}
    ext = os.path.splitext(policy_name)[1].lower()
    try:
        if ext == '.txt':
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        elif ext == '.pdf':
            reader = PdfReader(file_path)
            content = "\n\n".join(page.extract_text() or "" for page in reader.pages)
        elif ext == '.docx':
            doc = Document(file_path)
            content = "\n\n".join(para.text for para in doc.paragraphs)
        else:
            return {"status": "error", "error_message": "Unsupported format."}
        return {"status": "success", "content": content}
    except Exception as e:
        return {"status": "error", "error_message": str(e)}

def list_policy_documents() -> dict:
    folder_path = get_policies_path()
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    return {"status": "success", "files": files}

# def read_confluence_policy(space_key: str, page_title: str) -> dict:
#     try:
#         page = confluence.get_page_by_title(space=space_key, title=page_title, expand='body.storage')
#         if page:
#             content = page['body']['storage']['value']
#             return {"status": "success", "content": content}
#         else:
#             return {"status": "error", "error_message": f"Page not found."}
#     except Exception as e:
#         return {"status": "error", "error_message": str(e)}

policy_agent = Agent(
    name="policy_agent",
    model="gemini-2.5-flash",
    description="Reads policies from local files and answers to user questions from the policy files.",
    instruction="""
    Answer from local policies.
    Use read_policy_file/list_policy_documents for local.
    Example:
    What is mentioned about SLA in vulenerability management policy?
    Policy Agent will read vulnerabilty-manegment-policy.txt from local and will answer the question.
    As per open source license policy which license are categorized as copy left?
    Policy Agent will read open-source-license-policy.txt from local and will answer the question.
    """,
    tools=[read_policy_file, list_policy_documents]
)