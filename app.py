import hashlib
import json
from PIL import Image
import pytesseract
from PyPDF2 import PdfReader
from tkinter import Tk, Button, Label, filedialog, messagebox, Listbox, MULTIPLE, Text, Scrollbar, END
from web3 import Web3

# Load the contract ABI
with open("artifacts/contracts/DocumentVerification.sol/DocumentVerification.json", "r") as f:
    CONTRACT_ABI = json.load(f)["abi"]
    print(f"{CONTRACT_ABI}")

# Blockchain configuration
LOCAL_NODE_URL = "http://127.0.0.1:8545"  # Local node URL
CONTRACT_ADDRESS = "0x0165878A594ca255338adfa4d48449f69242Eb8F"  # Replace with your contract address
PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # Replace with your private key
ACCOUNT_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Replace with your account address

# Connect to the Ethereum node
web3 = Web3(Web3.HTTPProvider(LOCAL_NODE_URL))
if web3.is_connected():
    print("Connected to Ethereum node")
else:
    print("Failed to connect to Ethereum node")

# Create contract instance
contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

# OCR Function for Images
def extract_text_from_image(image_path):
    img = Image.open(image_path)
    text = pytesseract.image_to_string(img)
    return text

# Text Extraction Function for PDFs
def extract_text_from_pdf(pdf_path):
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    return text

def clean_text(text):
    return " ".join(text.split())

# Hashing Function
def generate_hash(text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text.encode("utf-8"))
    return sha256_hash.hexdigest()


# Store Hash on Blockchain
def store_hash_on_blockchain(hash_value):
    nonce = web3.eth.get_transaction_count(ACCOUNT_ADDRESS)

    print(f"📝 Storing Hash: {hash_value}")  # Debug print

    txn = contract.functions.storeHash(hash_value).build_transaction({
        "chainId": 1337,  # Hardhat network
        "gas": 2000000,
        "gasPrice": web3.to_wei("50", "gwei"),
        "nonce": nonce,
    })

    signed_txn = web3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
    txn_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    txn_receipt = web3.eth.wait_for_transaction_receipt(txn_hash)

    if txn_receipt.status == 1:
        print(f"✅ Hash stored successfully! Transaction Hash: {web3.to_hex(txn_hash)}")

        # Confirm that the hash count has increased
        total_hashes = contract.functions.hashCount().call()
        print(f"🔍 Updated Total Hashes on Blockchain: {total_hashes}")

        # Fetch and verify stored hash
        stored_hash = contract.functions.getHash(total_hashes - 1).call()
        print(f"📦 Last Stored Hash: {stored_hash}")

        return True
    else:
        print("❌ Failed to store hash on blockchain.")
        return False


# Verify Document   
def verify_document(file_path):
    if file_path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
        extracted_text = extract_text_from_image(file_path)
    elif file_path.lower().endswith(".pdf"):
        extracted_text = extract_text_from_pdf(file_path)
    else:
        raise ValueError("❌ Unsupported file format")

    if not extracted_text.strip():
        print("❌ No text found in document")
        return False

    # Generate the hash of extracted text
    current_hash = generate_hash(extracted_text)
    print(f"📄 Extracted Text: {extracted_text[:100]}...")  # Debug: Show part of extracted text
    print(f"🔢 Generated Hash: {current_hash}")

    # Get number of stored hashes from blockchain
    total_hashes = contract.functions.hashCount().call()
    print(f"🔍 Total Hashes on Blockchain: {total_hashes}")

    if total_hashes == 0:
        print("❌ No hashes stored on the blockchain yet.")
        return False

    # Iterate and compare stored hashes
    for index in range(total_hashes):
        stored_hash = contract.functions.getHash(index).call()
        print(f"📦 Stored Hash {index}: {stored_hash}")

        if current_hash == stored_hash:
            print(f"✅ Match found! Hash exists at index {index}")
            return True

    print("❌ No matching hash found.")
    return False


# GUI Application
class DocumentVerificationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Document Verification System")
        self.root.geometry("600x400")

        # Upload Section
        self.label = Label(root, text="Upload document(s)/image(s)/PDF(s) for verification", font=("Arial", 12))
        self.label.pack(pady=10)

        self.upload_button = Button(root, text="Upload Document(s)/Image(s)/PDF(s)", command=self.upload_files)
        self.upload_button.pack(pady=10)

        self.file_listbox = Listbox(root, selectmode=MULTIPLE, width=80, height=5)
        self.file_listbox.pack(pady=10)

        # Verification Section
        self.verify_button = Button(root, text="Verify Document(s)", command=self.verify_files)
        self.verify_button.pack(pady=10)

        # Output Section
        self.output_label = Label(root, text="Output:", font=("Arial", 12))
        self.output_label.pack(pady=10)

        self.output_text = Text(root, height=10, width=80)
        self.output_text.pack(pady=10)

        self.scrollbar = Scrollbar(root, command=self.output_text.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.output_text.config(yscrollcommand=self.scrollbar.set)

        self.file_paths = []

    def upload_files(self):
        self.file_paths = filedialog.askopenfilenames(
            title="Select Document(s)/Image(s)/PDF(s)",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp"), ("PDF Files", "*.pdf"), ("All Files", "*.*")]
        )
        self.file_listbox.delete(0, "end")
        for file_path in self.file_paths:
            self.file_listbox.insert("end", file_path)
        self.output_text.insert(END, f"{len(self.file_paths)} file(s) uploaded successfully.\n")

    def verify_files(self):
        if not self.file_paths:
            messagebox.showerror("Error", "No files uploaded!")
            return

        self.output_text.insert(END, "Verification Results:\n")
        for file_path in self.file_paths:
            try:
                if verify_document(file_path):
                    self.output_text.insert(END, f"{file_path}: Authentic\n")
                else:
                    self.output_text.insert(END, f"{file_path}: Not Authentic\n")
            except Exception as e:
                self.output_text.insert(END, f"{file_path}: Error - {str(e)}\n")

# Run the Application
if __name__ == "__main__":
    root = Tk()
    app = DocumentVerificationApp(root)
    root.mainloop()