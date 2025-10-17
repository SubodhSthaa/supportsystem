# check_model.py
from pathlib import Path

BERT_MODEL_PATH = Path("./it_support_model")

print("=== BERT Model Directory Analysis ===")
print(f"Path: {BERT_MODEL_PATH.absolute()}")
print(f"Exists: {BERT_MODEL_PATH.exists()}")

if BERT_MODEL_PATH.exists():
    files = list(BERT_MODEL_PATH.glob('*'))
    print(f"\n📁 Files found ({len(files)}):")
    for file in files:
        print(f"  - {file.name} ({file.stat().st_size / 1024:.1f} KB)")
    
    # Check required files
    required_files = ['pytorch_model.bin', 'config.json', 'vocab.txt']
    print(f"\n🔍 Required files check:")
    for req_file in required_files:
        file_path = BERT_MODEL_PATH / req_file
        exists = file_path.exists()
        size = file_path.stat().st_size if exists else 0
        print(f"  - {req_file}: {'✅' if exists else '❌'} ({size / 1024:.1f} KB)")
else:
    print("❌ Model directory doesn't exist!")